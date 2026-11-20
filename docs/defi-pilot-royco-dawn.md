# Royco Dawn detector pilot

This is an integration pilot, **not** a security audit or a vulnerability report.

## Source and environment

- Canonical source: <https://github.com/roycoprotocol/royco-dawn>
- Source commit: `d68947a1c52bf52b26455f7202f8b67b2494cc4b` (shallow checkout on 2026-11-06).
- The six Git submodules were checked out at the exact commits recorded by that source commit.
- Foundry config requests Solidity `0.8.34`, EVM `prague`, `via_ir=true`, optimizer runs `1666`, and build-info output.
- The adapter manifest captured 3,904 files and about 92.5 MB of source and dependencies. No deployed bytecode, chain ID, market address, or block was supplied for this pilot.

Royco's own README describes the tracked Junior impermanent-loss recovery behavior as a known deployed limitation. It must not be relabeled as a new exploit without a distinct violated property and realistic impact. Royco lists several Dawn audits and formal work on its [security page](https://www.royco.org/security); these are context, not proof that this source revision is safe.

The source-level review map identifies the Kernel's deposit/redeem and post-operation coverage checks, the Accountant's raw/effective NAV, impermanent-loss and yield/fee checkpoints, the Entry Point's pending deposit/redemption execution and cancellation paths, and the Factory/AccessManager/UUPS upgrade authority. Oracle quoters are integration boundaries. These are paths to test, not observed failures.

## Selected hypotheses

The EVM vault track selected 17 of the versioned 43 cards from observed features including accounting, ERC-4626 style tranches, oracle quoters, coverage/liquidation logic, UUPS upgrades, and pending entry-point requests. High priority groups include authorization/upgrade paths (`EVM-01`, `EVM-02`), state and callback paths (`EVM-03`, `EVM-04`), unit/rounding and share pricing (`EVM-09`, `EVM-10`, `ECO-01` to `ECO-03`), coverage/liquidation (`ECO-04`, `ECO-05`), oracle assumptions (`ECO-07`, `ECO-08`), rewards (`ECO-12`), and pending request settlement (`ECO-13`). The other 26 cards were deselected with reasons in the catalog output; deselection is not a pass.

## Execution result and limits

The exact-source manifest and catalog selection completed. A full `forge build --offline` began compiling 291 files with Solc 0.8.34 and did not finish within a practical pilot window. A narrower build still began compiling 211 files and was stopped after memory pressure warnings. No Slither result, successful transition coverage, counterexample, independent replay, or evidence record exists for Royco Dawn. The pilot therefore has **zero confirmed findings and no safety conclusion**. No live transaction or production signing key was used.

Next validation requires a resource-capped isolated build worker, a bounded targeted test/harness, source-to-deployed-bytecode correspondence, and a read-only fixed-block RPC path if a deployed claim is made. Compare any candidate with Royco's acknowledged behavior and prior audit findings before promotion.
