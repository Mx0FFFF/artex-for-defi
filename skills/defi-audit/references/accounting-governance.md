# Accounting, token, callback, and governance hypotheses

Use this catalog only for mechanisms present in the scoped protocol. Each item is a **test hypothesis**, not a finding. Pin the source revision and, for deployed targets, the chain, address, implementation, and block. Reproduce in a local test or local fork; record an observed loss or violated invariant and a negative control before reporting.

## Vault and share accounting

### First-depositor donation and exchange-rate inflation

- **Mechanism and preconditions:** A new or nearly empty vault calculates shares from its token balance. An attacker deposits a small amount, transfers assets directly to the vault, and changes the share price before another user deposits. Rounding can give the later user too few shares or zero shares. The attack depends on the actual conversion formula, seed liquidity, virtual assets/shares, slippage protections, and the attacker's recoverable share of the donation.
- **Local test:** Compare baseline `victim deposit → redeem` with `attacker seed deposit → direct donation → victim deposit → attacker redeem`. Assert minimum victim shares/value, and calculate attacker net profit after donation and fees. Sweep small deposits and the exact zero/one-share boundary. Remove the donation in the negative control.
- **False-positive control:** A changed `previewDeposit` alone is not an exploit. Account for virtual-share offsets, locked seed shares, withdrawal fees, and whether the attacker loses more than the victim. Verify the real asset is transferable directly to the vault.
- **Primary sources:** [ERC-4626 security considerations](https://eips.ethereum.org/EIPS/eip-4626), [OpenZeppelin ERC-4626 inflation analysis](https://docs.openzeppelin.com/contracts/5.x/erc4626).

### Directional rounding, previews, and fees

- **Mechanism and preconditions:** Deposit/mint/withdraw/redeem use different rounding directions. Fee-bearing vaults must make preview quotes consistent with the actual operation; an incorrect conversion can create unbacked shares, overpay a redeemer, or cause a user to receive less than the promised minimum.
- **Local test:** For boundary amounts and multiple decimal scales, compare `previewDeposit` with actual minted shares, `previewMint` with actual assets paid, `previewWithdraw` with shares burned, and `previewRedeem` with assets received. Repeat before/after a yield change and fee change. Assert aggregate redeemable claims do not exceed assets available under the protocol's accounting model.
- **False-positive control:** `convertTo*` is an estimate and need not equal an exact preview. Fees and deliberate rounding favoring the vault are allowed; show an exploitable discrepancy or broken specification, not just a one-unit difference.
- **Primary sources:** [ERC-4626 method and rounding rules](https://eips.ethereum.org/EIPS/eip-4626), [OpenZeppelin vault fee examples](https://docs.openzeppelin.com/contracts/5.x/erc4626).

## AMM and liquidity accounting

### Swap invariant, reserve synchronization, and LP mint/burn math

- **Mechanism and preconditions:** A v2-style pool enforces a fee-adjusted reserve invariant and computes liquidity shares from actual balances and prior reserves. Errors in fee application, balance-versus-reserve timing, or first-liquidity math can let a swap remove too much value or an LP mint/redeem disproportionate claims. Other AMM designs require their own invariant.
- **Local test:** Derive the pool's intended invariant from its code and docs. Generate swaps in both directions, dual-sided inputs, flash-swap callbacks, mint, burn, direct donations, and `sync`/`skim`-like paths. Assert the fee-adjusted invariant and LP proportional-claim bounds after each operation. Compare against a baseline without the attacker-controlled transfer/callback.
- **False-positive control:** Do not impose `x*y=k` on stable-swap, concentrated-liquidity, weighted, or intentionally dynamic-fee pools. Include protocol fees, rounding, token decimals, and minimum locked liquidity before calling a gain real.
- **Primary sources:** [Uniswap v2 whitepaper, fee-adjusted invariant and liquidity model](https://docs.uniswap.org/whitepaper.pdf), [Uniswap v2 pair implementation](https://github.com/Uniswap/v2-core/blob/master/contracts/UniswapV2Pair.sol).

## External token behavior and callbacks

### Fee-on-transfer, rebasing, and nonstandard return values

- **Mechanism and preconditions:** A protocol credits the nominal `transferFrom` amount while receiving less after a transfer fee, or assumes its token balance cannot change without an explicit transfer. This can desynchronize debt, shares, reserves, or reward claims. Some ERC-20s also omit a boolean return value; that is a distinct call-handling issue.
- **Local test:** With an actually supported or user-selectable asset, substitute local mocks for fee-on-transfer, negative/positive rebase, and no-return transfer behavior. Measure contract balance delta against minted shares/credited collateral and repeat withdrawal or liquidation. Assert liabilities remain backed and operations cannot be blocked by an expected token behavior.
- **False-positive control:** `SafeERC20` handles return-value differences but does not by itself correct amount accounting. Conversely, a protocol that explicitly excludes fee/rebasing assets has no such finding without a reachable path to admit one. A donation or positive rebase alone is not necessarily a loss.
- **Primary sources:** [Uniswap v2 router's actual-balance fee-on-transfer path](https://github.com/Uniswap/v2-periphery/blob/master/contracts/UniswapV2Router02.sol), [OpenZeppelin `SafeERC20` and wrapper balance caveat](https://docs.openzeppelin.com/contracts/5.x/api/token/erc20).

### State-changing and read-only reentrancy

- **Mechanism and preconditions:** An external call or token hook executes while a contract or one of its dependencies is partway through a state transition. A callback may reenter a mutating path or consume an inconsistent view value in a second contract, such as a temporarily distorted LP price. ERC-777 hooks make token transfer an explicit callback surface.
- **Local test:** Build a callback token/receiver or native-token recipient. Reenter each reachable deposit, withdraw, swap, claim, and price-read path at the external-call point. Snapshot balances, shares, debts, and any oracle value before, during, and after. Assert the protocol-specific invariant during callback as well as at transaction end, then disable the callback as a control.
- **False-positive control:** An external call is only a lead. Confirm that the token or recipient is attacker controlled, the callback is reachable, and an observer can use the transient state for an asset-moving action. A local `nonReentrant` modifier may not protect a cross-contract read-only path; equally, a guarded dependency or unconsumed view may remove the risk.
- **Primary sources:** [ERC-777 hook specification](https://eips.ethereum.org/EIPS/eip-777), [OpenZeppelin ReentrancyGuard behavior](https://docs.openzeppelin.com/contracts/4.x/api/security), [ChainSecurity's original Curve LP read-only reentrancy postmortem](https://www.chainsecurity.com/blog/curve-lp-oracle-manipulation-post-mortem).

## Rewards and emissions

### Reward-rate overflow, underfunding, and checkpoint order

- **Mechanism and preconditions:** A time-weighted reward accumulator may multiply elapsed time, reward rate, and precision before dividing by total stake. Extreme or incorrectly funded rates can overflow or make claims insolvent; updating stake before a user's reward checkpoint can shift rewards across participants. The exact risk depends on compiler arithmetic, rate bounds, and funding rules.
- **Local test:** Advance time across zero-supply, first-stake, additional-stake, exit, reward-top-up, and period-end boundaries. Assert paid plus outstanding rewards never exceeds funded rewards (within specified dust), and each user's earned amount matches the protocol's stated allocation. Test maximum permitted reward inputs and remove the extreme rate or reorder in a control.
- **False-positive control:** A mathematical high rate is not reachable if access control and funding/rate caps reject it. Intentional undistributed rewards during zero stake are a design choice; document the policy before classifying them as loss.
- **Primary source:** [Synthetix SIP-68's original reward-per-token overflow analysis](https://github.com/Synthetixio/SIPs/blob/master/content/sips/sip-68.md).

## Governance, upgrades, and authorization

### Flash-borrowed voting power or bypassed timelock

- **Mechanism and preconditions:** Governance reads current transferable balance instead of a prior snapshot, or a proposer/executor/admin route can make a privileged call without the expected vote and delay. Temporary capital may then be enough to change a protocol parameter within one transaction or short window.
- **Local test:** Borrow or mint voting units in the local environment, propose/vote/queue/execute, and check each lifecycle boundary and target role. Assert votes come from the specified historical timepoint and sensitive actions cannot execute before the declared delay. Repeat without borrowed votes and with an unprivileged caller.
- **False-positive control:** A same-block balance increase is harmless if votes are checkpointed at a past block/timepoint. Permissionless execution of an *already queued and matured* operation is often intentional. Distinguish an explicitly trusted admin power from unauthorized escalation.
- **Primary sources:** [OpenZeppelin Governor and timelock design](https://docs.openzeppelin.com/contracts/5.x/governance), [OpenZeppelin Votes checkpoint rationale](https://docs.openzeppelin.com/contracts/5.x/api/governance).

### Initialization, upgrade authority, and storage collisions

- **Mechanism and preconditions:** An initializer/reinitializer is callable by the wrong actor, the implementation remains take-overable, `_authorizeUpgrade` is weak, or a new implementation reinterprets prior storage slots. This can transfer ownership, change protocol economics, or corrupt balances even if the normal functions are safe.
- **Local test:** Resolve proxy, implementation, beacon, and admin at the pinned block. In a local clone/fork, try initialization and upgrade entry points from unprivileged actors. For an intended upgrade, compare storage layouts and selected balances/roles/debts before and after the upgrade; assert they remain semantically unchanged unless migration specifies otherwise. Test the intended initializer path as a control.
- **False-positive control:** Directly initializing an implementation is not automatically a proxy takeover; demonstrate the path from that state to proxy impact. A powerful but correctly assigned admin is a trust assumption unless the task's security policy forbids it.
- **Primary sources:** [OpenZeppelin upgradeable-contract rules](https://docs.openzeppelin.com/upgrades-plugins/writing-upgradeable), [OpenZeppelin UUPS upgrade authorization](https://docs.openzeppelin.com/contracts/4.x/api/proxy).

### Signature replay, wrong domain, and permit misuse

- **Mechanism and preconditions:** A signature-based authorization omits a consumed nonce, deadline, chain ID, verifying contract, operation type, or account binding. A valid signature may then authorize more than one action or the wrong deployment/chain. `permit` also allows a third party to submit the signed approval, so transaction ordering alone is not a flaw.
- **Local test:** Generate a valid signature for one actor, contract, chain, nonce, and deadline. Attempt the same signature twice, on a different contract/chain, after expiry, and with altered spender/value/action. Assert only the intended first authorization succeeds and balances/allowances reflect it. Model relayer front-running separately from unauthorized spending.
- **False-positive control:** A replayed *submission* that reverts after the first nonce use is expected. Show a second asset-moving authorization or blocked intended path, not merely that any caller may relay a permit.
- **Primary sources:** [ERC-2612 nonce, deadline, and domain requirements](https://eips.ethereum.org/EIPS/eip-2612), [EIP-712 typed-data domain](https://eips.ethereum.org/EIPS/eip-712).
