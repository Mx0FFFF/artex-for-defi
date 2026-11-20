export type DeFiScope = { kind: "contract" | "repository"; value: string };
export type DeFiAssetInput =
  | { type: "contract"; chain_id: number; address: string; protocol_name?: string; repository_url?: string }
  | { type: "repository"; repository_url: string; revision?: string; protocol_name?: string };

export type DeFiTargetInput = {
  protocolName: string;
  repositoryUrl: string;
  revision: string;
  chainId: string;
  contractAddresses: string;
  notes: string;
  hasUploadedFiles: boolean;
};

export const DEFAULT_DEFI_GOAL =
  "Review in-scope DeFi contracts and protocol logic for verifiable security vulnerabilities. For each finding, record the affected contracts, trigger conditions, asset impact, and minimal reproduction evidence.";

export function prepareDeFiTarget(input: DeFiTargetInput): {
  description: string;
  scope: DeFiScope[];
  assets: DeFiAssetInput[];
} {
  const protocolName = input.protocolName.trim();
  const revision = input.revision.trim();
  const notes = input.notes.trim();
  const chainText = input.chainId.trim();
  const addresses = [
    ...new Set(input.contractAddresses.split(/[\s,;]+/).map((value) => value.trim().toLowerCase()).filter(Boolean)),
  ];
  const repoText = input.repositoryUrl.trim();
  let repositoryUrl = "";

  if (repoText) {
    let parsed: URL;
    try {
      parsed = new URL(repoText);
    } catch {
      throw new Error("Enter the full HTTPS URL of the source repo");
    }
    if (
      parsed.protocol !== "https:" ||
      !parsed.hostname ||
      parsed.port ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash
    ) {
      throw new Error("Enter the full HTTPS URL of the source repo");
    }
    const path = parsed.pathname.replace(/\/+$/, "").replace(/\.git$/, "");
    if (!path || path === "/" || path.includes("//")) throw new Error("The source repo URL must include the repo path");
    parsed.pathname = path;
    repositoryUrl = parsed.toString();
  }

  if (revision && !repositoryUrl) throw new Error("If you set a code version, also provide the source repo URL");
  if (revision.length > 128 || /[\s#]/.test(revision)) {
    throw new Error("Code version can't exceed 128 characters or contain spaces or #");
  }

  let chainId: number | undefined;
  if (chainText) {
    if (!/^[1-9]\d*$/.test(chainText)) throw new Error("Chain ID must be a positive integer");
    chainId = Number(chainText);
    if (!Number.isSafeInteger(chainId)) throw new Error("Chain ID is out of supported range");
  }
  if (addresses.length && chainId === undefined) throw new Error("If you enter a contract address, also enter the chain ID");
  for (const address of addresses) {
    if (!/^0x[0-9a-f]{40}$/.test(address)) throw new Error(`Invalid contract address format: ${address}`);
  }
  if (!repositoryUrl && addresses.length === 0 && !notes && !input.hasUploadedFiles) {
    throw new Error("Enter a source repo, contract address or code path, or upload contract source");
  }

  const scope: DeFiScope[] = [];
  const assets: DeFiAssetInput[] = [];
  if (repositoryUrl) {
    scope.push({ kind: "repository", value: revision ? `${repositoryUrl}#${revision}` : repositoryUrl });
    assets.push({
      type: "repository",
      repository_url: repositoryUrl,
      ...(revision && { revision }),
      ...(protocolName && { protocol_name: protocolName }),
    });
  }
  if (chainId !== undefined) {
    for (const address of addresses) {
      scope.push({ kind: "contract", value: `eip155:${chainId}:${address}` });
      assets.push({
        type: "contract",
        chain_id: chainId,
        address,
        ...(protocolName && { protocol_name: protocolName }),
        ...(repositoryUrl && { repository_url: repositoryUrl }),
      });
    }
  }

  const parts = ["DeFi protocol security review"];
  if (protocolName) parts.push(`Protocol: ${protocolName}`);
  if (repositoryUrl) parts.push(`Source repository: ${repositoryUrl}`);
  if (revision) parts.push(`Code revision: ${revision}`);
  if (chainId !== undefined) parts.push(`Chain ID: ${chainId}`);
  if (addresses.length) parts.push(`Contract addresses:\n${addresses.join("\n")}`);
  if (notes) parts.push(`Additional context and review scope:\n${notes}`);
  return { description: parts.join("\n"), scope, assets };
}
