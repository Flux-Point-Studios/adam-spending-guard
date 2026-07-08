# Spending-Guard v2 — Pinnable (client-attestable) design spike

> **STATUS: design spike, red-team GREEN — NOT production.** The deployed guard
> is v1 (parameterized). This branch proves the pinnable redesign is viable and
> survives an adversarial red-team; productionizing it (full test port + gateway/
> SDK/tx-builder wiring + external review) is scoped below.

## Why

The mainnet gate needs the partner wallet to **independently attest** that a
guard deposit funds a genuine guard owned by the user's own key — without
trusting the gateway. On iOS (CSLKit) the wallet can **hash a script → address**
but has **no `apply_params_to_script`**. v1 parameterizes the guard by
`(owner, stt_policy, stt_name)`, so its address can't be re-derived hash-only →
the owner-substitution case (INFO-1) isn't client-verifiable.

## What changed

1. **Guard script is UNPARAMETERIZED** (`validators/guard.ak`) → one universal
   address the wallet pins by hashing the compiled code. No apply_params.
2. **STT policy is UNIVERSAL** (`validators/state_token.ak`) → pinnable policy
   id. Uniqueness moves from a script param to the token **name**:
   `name = blake2b_256(cbor.serialise(genesis OutputReference))`, minted only if
   that genesis UTxO is consumed (one-shot; +1 only; burn −1 only).
3. **`owner` and `stt_policy` move INTO the datum** (`lib/guard/types.ak`). The
   agent branch keeps them immutable (datum-invariance). The STT name is read
   dynamically from the spent input.

## What the wallet attests (hash-only, no apply_params)

- deposit's guard output address == **pinned** universal guard address
- the STT is the **pinned** universal policy, minted +1, and its **name ==
  `hash(a genesis input in this deposit)`**
- `datum.owner == my own key`  → the user can always sweep
- `datum.stt_policy == pinned STT policy`
- caps (`per_tx_cap` / `daily_cap` / `min_principal` / `expiry`) == what the user
  consented to

Everything the "can't exceed your caps / you can always withdraw" promise rests
on is now client-verifiable.

## Red-team verdict

`aiken-validator-redteam` (16 agents, every eUTxO class + novel round, PoC
fund-stealing txs compiled, skeptic-verified with ledger-consistency enforced):
**GREEN — 0 confirmed vulns, 0 even claimed.** The new surface was hammered and
defended: universal-STT forgery (mint without a genesis, name collision,
parallel-guard accumulator reset), the **shared universal address** (double-
satisfaction / cross-guard siphon — the "exactly one guard-address input" check
holds), and datum-carried owner/policy. Baseline suite: 12/12 honest + invariant
tests green.

## To productionize (before mainnet)

1. Port the full v1 adversarial suite (29 tests) + the ledger-consistency window
   proofs to the v2 datum shape; re-run the red-team on the final.
2. Gateway: `GuardDatum` gains `owner` + `stt_policy`; `state_token` becomes
   unparameterized; `guard` unparameterized; the deploy tx builder mints the STT
   named `blake2b(genesis)` and sets the datum owner = the user's payment key.
3. AdamKit / gateway: surface the pinned guard address + STT policy id (from the
   v2 `plutus.json`) so the wallet can hardcode them.
4. External review of the shared-address singleton + the name-by-genesis STT
   (new surface vs v1).
