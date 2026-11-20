# Current high-signal surfaces

Use this catalog only for mechanisms the scoped protocol actually has. Every item
is a **test hypothesis**, not a finding. Each entry gives the mechanism, where to
look, a concrete local check (a Foundry test, and a symbolic `check_` property
where one fits), the usual disqualifiers, and the detector-card IDs whose sourced
guidance to pull. Reproduce in a local test or pinned fork, show a violated
invariant and a negative control, and never broadcast to a live chain.

Turn an invariant into a halmos property: write `check_<name>(symbolic args)` that
sets up reachable state, performs the operation, and `assert`s the property.
`run_analysis.py run halmos --match-test check_<name>` returns a counterexample
(candidate), a bounded pass, or `incomplete`. A counterexample must still be
reproduced with a concrete Foundry test before promotion.

## Approval drain through arbitrary external calls

- **Mechanism:** A router, aggregator, migrator, or "multicall" forwards an
  attacker-controlled target/calldata while the contract holds users' ERC-20
  approvals or custody. The attacker passes `target=token, data=transferFrom(victim,attacker,amount)`
  or an approve/permit, draining anyone who approved the contract.
- **Where to look:** `call`/`functionCall`/`delegatecall` with a target or selector
  derived from calldata; swap/zap/migrate/claim routes; callbacks that re-enter with
  user-supplied addresses; "rescue"/"sweep" helpers.
- **Local test / property:** From an unprivileged caller, invoke the external-call
  entry with a token and `transferFrom`/`approve` payload against a victim who only
  granted a normal allowance. `check_` property: *no sequence of public calls moves
  a non-caller's tokens or allowance.* Assert victim balance/allowance unchanged.
- **Disqualifiers:** Target/selector allowlisted to trusted protocol contracts;
  no standing approvals or custody; pull-only accounting. A reachable arbitrary call
  with no asset/approval to abuse is a lead, not a loss.
- **Cards:** EVM-11, EVM-05, EVM-08.

## Uninitialized or re-initializable proxies and weak upgrade authority

- **Mechanism:** An implementation is left initializable, a `reinitializer` is
  callable by the wrong actor, `_authorizeUpgrade` is missing/weak, or a new
  implementation reinterprets prior storage slots. Any of these transfers ownership
  or corrupts balances even when ordinary functions are safe.
- **Where to look:** `initialize`/`__init`/`reinitializer`, `_disableInitializers`
  in the constructor, `_authorizeUpgrade`, UUPS vs transparent vs beacon, storage gaps.
- **Local test / property:** Resolve proxy/implementation/admin at the pinned block;
  from an unprivileged actor try initialize and upgrade. For an intended upgrade,
  compare storage layout and selected balances/roles before/after. `check_` property:
  *only the configured admin can change implementation; initialize cannot run twice.*
- **Disqualifiers:** Directly initializing the *implementation* (not the proxy) with
  no path to proxy impact; a correctly assigned powerful admin is a trust assumption
  unless the task policy forbids it.
- **Cards:** EVM-02, EVM-01.

## Signature and `ecrecover` edge cases

- **Mechanism:** `ecrecover` returns `address(0)` for malformed signatures, so a
  missing `signer != 0` / zero-address-admin check authorizes forged input. Also:
  omitted nonce, deadline, chain ID, verifying contract, or operation type lets one
  signature authorize twice or on the wrong deployment; unbounded `s`/`v` malleability;
  `permit` front-running treated as a bug.
- **Where to look:** `ecrecover`, EIP-712 digest construction, EIP-2612 `permit`,
  ERC-1271 `isValidSignature`, nonce maps, `DOMAIN_SEPARATOR` caching across chain IDs.
- **Local test / property:** Recover with a bad signature and confirm it is rejected
  (not mapped to a zero-address authority); replay a valid signature twice, on another
  chain/contract, after expiry, with mutated spender/value. `check_` property:
  *recovered signer is nonzero and the digest binds every execution-relevant field;
  a nonce is consumed exactly once.* halmos is strong here over symbolic `v,r,s`.
- **Disqualifiers:** A replayed submission that reverts after first nonce use; a
  relayer submitting a user's own `permit` is expected.
- **Cards:** EVM-06, EVM-12.

## Cross-contract and read-only reentrancy

- **Mechanism:** An external call or token hook (ERC-777/ERC-721 `onReceived`, native
  send, ERC-4626 callbacks) runs mid-transition. A callback re-enters a mutating path,
  or a *second* contract reads a transiently inconsistent view (e.g., an LP/vault
  price) during the callback window.
- **Where to look:** external calls before state settles; view functions used as
  oracles by other contracts; `nonReentrant` on writes but not on the read consumed
  elsewhere; Curve-style LP valuation.
- **Local test / property:** Reenter each deposit/withdraw/swap/claim at the call
  point; snapshot the protocol invariant *during* callback and at tx end; have a
  second contract consume the view mid-callback. Negative control: disable the hook.
- **Disqualifiers:** Token/recipient not attacker-controlled; the transient view is
  never consumed by an asset-moving action.
- **Cards:** EVM-03, EVM-04.

## Rounding direction and dust amplification

- **Mechanism:** Deposit/withdraw/mint/redeem or interest/reward math round in a
  direction that favors the caller, and the gain repeats across many tiny operations
  until it is material. Mixed token/share decimals and truncating division compound it.
- **Where to look:** division before multiplication, `mulDiv` rounding flags,
  `convertToShares`/`convertToAssets` asymmetry, fee math, index/accumulator updates.
- **Local test / property:** Loop the suspect op at the 0/1-unit boundary and compare
  aggregate user claims vs protocol assets. `check_` property: *round-trip
  deposit→redeem never returns more than deposited (minus fees); total claims ≤ assets.*
  halmos finds the exact adversarial amount a fuzzer misses.
- **Disqualifiers:** Rounding deliberately favors the vault; one-unit differences with
  no repeatable extraction.
- **Cards:** EVM-09, ECO-03.

## First-deposit inflation and empty-vault share pricing

- **Mechanism:** A new/near-empty ERC-4626-style vault derives shares from its token
  balance; an attacker seeds one wei, donates assets directly, and inflates share
  price so the next depositor gets zero/too few shares.
- **Local test / property:** Compare `victim deposit→redeem` baseline against
  `attacker seed → direct donation → victim deposit → attacker redeem`; sweep the
  zero/one-share boundary; account for the attacker's irrecoverable donation and any
  virtual offset. `check_` property: *a victim depositing `d` always redeems value ≥ `d` minus declared fees.*
- **Disqualifiers:** Virtual shares/assets offset, locked seed shares, or
  dead-shares on first mint make extraction uneconomic; a changed `previewDeposit`
  alone is not theft.
- **Cards:** EVM-10, ECO-01, ECO-02.

## Price inputs: spot, TWAP, freshness, scale, sequencer

- **Mechanism:** A value-sensitive sink (borrow, mint, liquidation, settlement) reads
  a manipulable spot/`slot0` price, a too-short/stale TWAP, a feed with mishandled
  decimals or inverted pair, or an L2 price while the sequencer is down/just-recovered.
- **Local test / property:** Identify the exact sink; move pool state within a tx (and
  across the minimum blocks the TWAP requires) and compare borrowing benefit to full
  manipulation cost at the target's real liquidity; mock stale/zero/negative feed and
  sequencer-down states on each price path; verify orientation/decimals with known amounts.
- **Disqualifiers:** DEX execution naturally uses current prices; a transient
  discrepancy with no value-sensitive consumer; adequate history/liquidity caps.
- **Cards:** ECO-07, ECO-08, ECO-09.

## L2 and cross-domain sender identity

- **Mechanism:** On L2/bridged paths, `msg.sender` is a gateway/aliased address, not
  the original caller, and the same address on another chain is a different authority.
  Trusting a raw sender or a default/zero source accepts unauthenticated messages.
- **Local test / property:** For each privileged receive path, vary source chain,
  source contract, and gateway independently; assert only the configured tuple can
  mint/release/upgrade; test the L1→L2 aliasing rule explicitly.
- **Disqualifiers:** A faithfully modeled gateway with correct source validation; a
  mocked verifier returning `true` proves only the mock.
- **Cards:** X01, ECO-09, EVM-01.

## Account abstraction and EIP-7702

- **Mechanism:** ERC-4337 and EIP-7702 break two old heuristics: `tx.origin == msg.sender`
  no longer identifies an EOA, and an EOA can carry delegated code and act like a
  contract (callbacks, reentrancy, `isContract` bypass). Validation-vs-execution
  separation and paymaster trust add surface.
- **Where to look:** `tx.origin` auth checks, `isContract`/`code.length==0` gating,
  "EOA-only" modifiers, signature validation in `validateUserOp`, delegate storage.
- **Local test / property:** Call "EOA-only" paths from a 7702-delegated account and a
  4337 smart account; reenter via a delegated EOA. `check_` property: *authorization
  does not depend on `tx.origin` or on `code.length==0` to mean "trusted EOA".*
- **Disqualifiers:** Checks that tolerate smart accounts by design.
- **Cards:** EVM-14, EVM-01, EVM-05.

## Uniswap v4 hooks and transient storage

- **Mechanism:** v4 hooks run attacker-reachable code at pool lifecycle points, and
  transient storage (`TSTORE`/`TLOAD`, EIP-1153) holds locks/accumulators that must be
  cleared within the transaction. A hook with excess permissions, a mis-scoped lock,
  or a transient value read after it should be cleared breaks accounting or re-enters.
- **Where to look:** hook permission bits, `unlock`/callback flow, transient
  reentrancy guards, flash-accounting deltas settled at unlock.
- **Local test / property:** Exercise each enabled hook callback from an adversarial
  pool/token; assert deltas net to zero at unlock and transient locks are cleared;
  reenter through the hook. `check_` property: *every transient slot the op sets is
  zero at transaction end; flash-accounting balances settle.*
- **Disqualifiers:** Hooks with no economic callback; correctly scoped transient locks.
- **Cards:** EVM-14, EVM-03, EVM-05.

## Liquid staking, restaking, and queued withdrawals

- **Mechanism:** Value hides in deposit queues, TVL buckets, and withdrawal-delay
  accounting. Shares minted before backing arrives, slashing not reflected in the
  exchange rate, or a withdrawal queue that lets later requesters jump or double-claim
  break conservation.
- **Local test / property:** Model request→pending→claimable→claimed across epochs and
  slashing; assert paid + pending ≤ backed assets and each request settles once.
  `check_` property over queue indices and amounts.
- **Disqualifiers:** Intended delay/illiquidity; documented slashing socialization.
- **Cards:** ECO-13, ECO-12, EVM-10.

## Token integration gap: requested vs received

- **Mechanism:** The protocol credits the nominal `transferFrom` amount but receives
  less (fee-on-transfer), more/less later (rebasing), gets no boolean return, or the
  token re-enters via a transfer hook. Accounting desyncs from real balances.
- **Local test / property:** With a user-selectable or supported asset, substitute
  local mocks for fee-on-transfer, rebase, no-return, and callback tokens; compare
  measured balance delta to credited shares/collateral; repeat withdrawal/liquidation.
  `check_` property: *credited amount equals measured received amount.*
- **Disqualifiers:** The asset set is fixed and excludes such tokens with no reachable
  path to admit one; `SafeERC20` fixes return-value handling but not amount accounting.
- **Cards:** EVM-08, ECO-03.

---

Record outcomes in the shared review ledger (`defi_analysis ledger-status` /
`ledger-cover`): a selected card with zero successful transitions is untested, not
safe. Map every reproduced issue to one of the card `detector_ids` so the evidence
record and `report_finding` stay consistent.
