import { activeMention, mentionKinds, mentionSearch, mentionToken, selectedMentions } from "./chat-mentions.ts";
import assert from "node:assert/strict";
import test from "node:test";

test("mention trigger supports Chinese and cursor placement without hijacking email", () => {
  assert.equal(activeMention("user@example.com", 16), null);
  assert.equal(activeMention("已选 @[漏洞#1 X]", 12), null);
  assert.deepEqual(activeMention("查看@漏洞 后面的文字", 5), { start: 2, end: 5, query: "漏洞" });
  assert.equal(activeMention("@漏洞\n下一行", 8), null);
});

test("categories, Chinese aliases, IP and keyword search", () => {
  assert.deepEqual(mentionSearch("").categories, mentionKinds);
  assert.equal(mentionSearch("Vulnerability #12").kind, "finding");
  assert.equal(mentionSearch("finding example").query, "example");
  assert.equal(mentionSearch("漏").categories[0].kind, "finding");
  assert.equal(mentionSearch("漏洞").kind, "finding");
  assert.equal(mentionSearch("漏洞SQL注入").query, "SQL注入");
  assert.equal(mentionSearch("ip 192.0.2.1").kind, "ip");
  assert.equal(mentionSearch("接口 GET /api").query, "GET /api");
  assert.equal(mentionSearch("acme.com").kind, "");
});

test("tokens roundtrip labels and removing one reference preserves its neighbors", () => {
  const first = mentionToken({ kind: "finding", id: 12, label: "标题[1]\n描述" });
  const second = mentionToken({ kind: "ip", id: 13, label: "192.0.2.1" });
  const legacy = "@[漏洞#14 标题（1） 描述]";
  const value = `分析 ${first} 和 ${second} ${legacy}`;
  const selected = selectedMentions(value);
  assert.equal(selected.length, 3);
  assert.equal(selected[0].label, "Vulnerability #12 · 标题(1) 描述");
  assert.equal(selected[2].label, "漏洞 #14 · 标题（1） 描述");
  const next = value.slice(0, selected[0].start) + value.slice(selected[0].start + selected[0].token.length);
  assert.equal(selectedMentions(next)[0].token, second);
});

test("every supported category roundtrips both current and saved mention tokens", () => {
  for (const { kind, label, zh } of mentionKinds) {
    const current = mentionToken({ kind, id: 7, label: "item" });
    assert.equal(current, `@[${label}#7 item]`);
    const saved = `@[${zh}#7 item]`;
    assert.deepEqual(
      selectedMentions(`${saved} ${current}`).map((item) => item.token),
      [saved, current],
    );
    assert.equal(mentionSearch(zh).kind, kind);
  }
});
