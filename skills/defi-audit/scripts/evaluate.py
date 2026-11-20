#!/usr/bin/env python3
"""Score independently adjudicated DeFi detector runs against sealed cases.

Ground truth and adjudicated matches belong outside the worker's workspace. This
program computes metrics; it does not judge whether a claimed exploit is real.
"""

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path

SPLITS = {"development", "private_validation", "sealed_test"}
REPORTABLE = {"confirmed"}
RUN_STATUSES = ("completed", "incomplete", "blocked", "unknown")


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def _reject_constant(value):
    raise ValueError(f"nonfinite JSON value: {value}")


def _read_document(path, key):
    data = json.loads(Path(path).read_text(encoding="utf-8"),
                      parse_constant=_reject_constant)
    if not isinstance(data, dict) or not isinstance(data.get(key), list):
        raise ValueError(f"{path} must contain a {key} array")
    return data


def score(cases, predictions, case_runs=()):
    by_case = {}
    families = {}
    leakage_groups = {}
    for case in cases:
        case_id = case.get("case_id")
        split = case.get("split")
        family = case.get("protocol_family")
        truths = case.get("expected_root_causes")
        if not all(isinstance(v, str) and v for v in (case_id, split, family)):
            raise ValueError("case_id, split, and protocol_family are required strings")
        if split not in SPLITS or not isinstance(truths, list) or any(
            not isinstance(x, str) or not x for x in truths
        ) or len(truths) != len(set(truths)):
            raise ValueError(f"invalid split or ground truth for {case_id}")
        if case_id in by_case:
            raise ValueError(f"duplicate case_id: {case_id}")
        if family in families and families[family] != split:
            raise ValueError(f"protocol family {family} leaks across splits")
        families[family] = split
        groups = case.get("leakage_groups", [])
        if not isinstance(groups, list) or any(not isinstance(group, str) or not group for group in groups):
            raise ValueError(f"invalid leakage_groups for {case_id}")
        for group in groups:
            if group in leakage_groups and leakage_groups[group] != split:
                raise ValueError(f"exploit/root-cause family {group} leaks across splits")
            leakage_groups[group] = split
        by_case[case_id] = case

    if not isinstance(case_runs, (list, tuple)):
        raise ValueError("case_runs must be an array")
    run_status = {}
    for run in case_runs:
        if not isinstance(run, dict):
            raise ValueError("case_runs entries must be objects")
        case_id = run.get("case_id")
        status = run.get("status", "unknown")
        if not isinstance(case_id, str) or case_id not in by_case:
            raise ValueError("case_runs entry needs a known case_id")
        if case_id in run_status:
            raise ValueError(f"duplicate case_runs entry for {case_id}")
        if status not in RUN_STATUSES:
            raise ValueError(f"invalid run status for {case_id}: {status}")
        run_status[case_id] = status

    predicted = defaultdict(list)
    seen_predictions = set()
    for item in predictions:
        case_id = item.get("case_id")
        finding_id = item.get("finding_id")
        if case_id not in by_case or not isinstance(finding_id, str) or not finding_id:
            raise ValueError("prediction needs a known case_id and finding_id")
        if (case_id, finding_id) in seen_predictions:
            raise ValueError(f"duplicate prediction {case_id}/{finding_id}")
        seen_predictions.add((case_id, finding_id))
        if item.get("status") not in {"hypothesis", "statically_supported", "reproduced", "confirmed", "refuted", "blocked", "not_applicable"}:
            raise ValueError(f"invalid status for {case_id}/{finding_id}")
        matched = item.get("adjudicated_root_cause_id")
        if matched is not None and (not isinstance(matched, str) or not matched):
            raise ValueError("adjudicated_root_cause_id must be a string or null")
        for field in ("cost_usd", "duration_seconds"):
            value = item.get(field, 0)
            if type(value) not in (int, float) or value < 0 or value > 1e12 or (type(value) is float and not math.isfinite(value)):
                raise ValueError(f"{field} must be finite, nonnegative, and at most 1e12")
        predicted[case_id].append(item)

    result = {}
    for split in sorted(SPLITS):
        split_cases = [c for c in cases if c["split"] == split]
        total_truth = sum(len(c["expected_root_causes"]) for c in split_cases)
        true_positive = false_positive = blocked = clean_with_fp = duplicates = reproduced_only = 0
        cost = duration = 0.0
        found_by_class = defaultdict(lambda: {"found": 0, "total": 0})
        run_counts = dict.fromkeys((*RUN_STATUSES, "missing"), 0)
        completed_clean = completed_clean_with_fp = 0
        for case in split_cases:
            cid = case["case_id"]
            status = run_status.get(cid, "unknown" if predicted.get(cid) else "missing")
            run_counts[status] += 1
            truth = set(case["expected_root_causes"])
            for root in truth:
                found_by_class[root]["total"] += 1
            found = set()
            case_false_positive = False
            for item in predicted[cid]:
                cost += item.get("cost_usd", 0)
                duration += item.get("duration_seconds", 0)
                if item["status"] == "blocked":
                    blocked += 1
                if item["status"] == "reproduced":
                    reproduced_only += 1
                if item["status"] not in REPORTABLE:
                    continue
                match = item.get("adjudicated_root_cause_id")
                if match in truth and match not in found:
                    found.add(match)
                    true_positive += 1
                    found_by_class[match]["found"] += 1
                else:
                    false_positive += 1
                    case_false_positive = True
                    if match in found:
                        duplicates += 1
            if not truth and case_false_positive:
                clean_with_fp += 1
            if not truth and status == "completed":
                completed_clean += 1
                completed_clean_with_fp += int(case_false_positive)
        clean_cases = sum(not c["expected_root_causes"] for c in split_cases)
        precision = ratio(true_positive, true_positive + false_positive)
        recall = ratio(true_positive, total_truth)
        result[split] = {
            "cases": len(split_cases),
            "ground_truth_root_causes": total_truth,
            "true_positive_findings": true_positive,
            "false_positive_findings": false_positive,
            "duplicate_reported_findings": duplicates,
            "blocked_checks": blocked,
            "reproduced_unconfirmed_candidates": reproduced_only,
            "precision": precision,
            "recall": recall,
            "f1": (2 * precision * recall / (precision + recall)) if precision is not None and recall is not None and precision + recall else None,
            "clean_case_false_positive_rate": ratio(clean_with_fp, clean_cases),
            "clean_cases_in_manifest": clean_cases,
            "case_runs": {
                "by_status": run_counts,
                "completion_rate": ratio(run_counts["completed"], len(split_cases)),
                "completed_clean_cases": completed_clean,
                "completed_clean_cases_with_false_positive": completed_clean_with_fp,
                "completed_clean_case_false_positive_rate": ratio(completed_clean_with_fp, completed_clean),
            },
            "cost_usd": round(cost, 6),
            "duration_seconds": round(duration, 3),
            "cost_per_true_positive_usd": ratio(cost, true_positive),
            "seconds_per_true_positive": ratio(duration, true_positive),
            "per_root_cause": dict(sorted(found_by_class.items())),
        }
    return {"metrics": result, "note": (
        "An independent evaluator assigns matches and run statuses. Recall uses all expected root causes. "
        "The historical clean_case_false_positive_rate uses all clean cases in the manifest, "
        "including cases with unknown or missing results. See case_runs for completed controls."
    )}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", required=True, help="evaluator-only case manifest")
    parser.add_argument("--predictions", required=True, help="independently adjudicated predictions")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    cases = _read_document(args.cases, "cases")["cases"]
    adjudicated = _read_document(args.predictions, "predictions")
    output = score(cases, adjudicated["predictions"], adjudicated.get("case_runs", ()))
    Path(args.output).write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote evaluation metrics to {args.output}")


if __name__ == "__main__":
    main()
