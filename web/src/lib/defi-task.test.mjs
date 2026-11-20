import { strict as assert } from "node:assert";
import { test } from "node:test";

import { prepareDeFiTarget } from "./defi-task.ts";

const emptyTarget = {
  protocolName: "",
  repositoryUrl: "",
  revision: "",
  chainId: "",
  contractAddresses: "",
  notes: "",
  hasUploadedFiles: false,
};

test("DeFi targets produce canonical, deduplicated contract scopes", () => {
  const address = `0x${"ab".repeat(20)}`;
  const result = prepareDeFiTarget({
    ...emptyTarget,
    protocolName: "Vault",
    repositoryUrl: "https://github.com/example/vault",
    revision: "v1.0.0",
    chainId: "1",
    contractAddresses: `${address.toUpperCase().replace("0X", "0x")}\n${address}`,
  });
  assert.deepEqual(result.scope, [
    { kind: "repository", value: "https://github.com/example/vault#v1.0.0" },
    { kind: "contract", value: `eip155:1:${address}` },
  ]);
  assert.match(result.description, /Code revision: v1\.0\.0/);
  assert.deepEqual(
    prepareDeFiTarget({ ...emptyTarget, repositoryUrl: "https://github.com/example/vault.git/" }).scope,
    [{ kind: "repository", value: "https://github.com/example/vault" }],
  );
});

test("DeFi target validation rejects ambiguous or malformed contract scope", () => {
  const address = `0x${"ab".repeat(20)}`;
  assert.throws(() => prepareDeFiTarget({ ...emptyTarget, contractAddresses: address }), /chain ID/);
  assert.throws(() => prepareDeFiTarget({ ...emptyTarget, chainId: "1", contractAddresses: "0x1234" }), /Invalid contract address format/);
  assert.throws(() => prepareDeFiTarget({ ...emptyTarget, repositoryUrl: "http://example.com/repo" }), /HTTPS/);
});
