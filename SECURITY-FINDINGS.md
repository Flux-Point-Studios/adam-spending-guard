# Security findings — ADAM guard v2 (`v2-pinnable-spike`)

> **RESOLUTION (F-1, F-2): FIXED** — `agent_spend_ok` now enforces token
> conservation (`non_ada_conserved`): every native asset on the guard input must
> remain on the continuation at ≥ its input quantity, so the agent can only
> *acquire* tokens, never move them out. The two reproducers are flipped to `fail`
> (now reject) in `security_findings_test.ak`, a `buy_grows_token_position_accepted`
> test proves acquisition still works, and a focused red-team of the fixed
> validator returned **GREEN** (0 confirmed across token_exfil / value / mint /
> continuation / composed / double_sat). Autonomous *selling* of declared tokens is
> being added via per-asset sliding-window quantity caps (next branch). F-3 stays a
> threat-model note. Thanks to the reviewer — precise, reproducible, correct.

Independent red-team of `agent_spend_ok` (`lib/guard/logic.ak`). Every finding below
is **confirmed by execution** (`aiken check`, aiken v1.1.16, stdlib v3.1.0) — see
`validators/security_findings_test.ak` for runnable reproducers.

Summary: the shared universal-address **singleton defense is sound** (see "Not a
finding"). But the guard meters **lovelace only** — it does not conserve or cap the
UTxO's **native tokens** — so the agent branch can move arbitrary non-ADA assets out
of the guard with no cap, no daily accounting, and no audit record.

---

## F-1 (High): native-token exfiltration — lovelace-only metering

**Confirmed:** `logic.spend_ok(datum, AgentSpend, own_ref, tx)` returns **`True`** for
a tx that keeps ADA within caps but ships the guard's native tokens to an attacker.

Repro (`security_findings_test.ak :: known_gap_token_exfiltration_accepted`):

- Guard input: `100 ADA + 1000·T + 1·STT` (T = any non-STT asset).
- Continuation → guard address: `100 ADA + 1·STT` (T **dropped**).
- Separate output → attacker: `1000·T`.
- Agent-signed, within skew, not expired, datum forwarded unchanged.

Every clause passes: `outflow = lovelace_of(guard_in) − lovelace_of(cont) = 0`, so
`per_tx_ok / daily_ok / floor_ok` are trivially satisfied; `assets_ok` only bounds the
**count** of assets on the continuation (dropping T lowers it); `datum_ok` holds
because the datum is unchanged (token value is not part of the datum). The STT and ADA
are conserved, so the guard sees "nothing left."

**Impact.** For an agent that ever holds non-ADA value in the guard — which an ADAM
trading bot does whenever it buys a token — the guard provides **no protection at all**
on that value. A compromised/malicious session key (or server) drains it in one tx.

**Root cause.** `outflow`, the per-tx and daily caps, and the principal floor are all
defined purely on `lovelace_of(...)`. Non-lovelace value is never compared between
`guard_in` and `cont`.

**Suggested direction (author's call).** Conserve/meter native tokens explicitly, e.g.
require the continuation to retain the guard's non-ADA multiasset (minus an allowed,
metered outflow), or forbid non-ADA assets leaving the guard on the agent branch
entirely. Any of these closes F-1 and F-2 together.

---

## F-2 (High): token drain hidden by negative outflow — no spend record

**Confirmed:** returns **`True`** for a drain where the agent *adds* ADA so
`ada_out > ada_in`.

Repro (`known_gap_negative_outflow_token_drain_accepted`):

- Guard input: `50 ADA + 500·T + STT`; continuation: `60 ADA + STT` (T dropped, ADA up).

`outflow = −10 ADA`, so caps pass; and because the record branch is
`if outflow > 0 { [record, ..] } else { active }`, **no `SpendRecord` is written** —
the rolling daily window never even observes the movement. Same root cause as F-1, and
it additionally shows the daily accounting is blind to any non-positive-lovelace tx.

---

## F-3 (Low / defense-in-depth): guard doesn't constrain the rest of the universal STT policy

`no_stt_mint = quantity_of(tx.mint, datum.stt_policy, stt_nm) == 0` pins only *this
guard's* STT name. A mint of a **different** name under the same universal
`stt_policy`, in the same tx, passes every clause in `agent_spend_ok`. This is not a
theft of the guard being spent — uniqueness of the universal policy is enforced by the
**separate** `state_token` minting policy — but it means the guard silently depends on
that external validator for the policy's singleton invariant. Worth a one-line note in
the guard's threat model. (Not included as a failing reproducer; it's arguably by
design.)

---

## Not a finding: shared-address singleton double-satisfaction

The universal script address is shared across all owners' guards, distinguished only by
STT name. We specifically tried to break per-guard accounting by co-locating a second
guard (or a foreign UTxO) at the address. **The defense holds:**
`expect [guard_in] = <inputs at guard address>` admits exactly one guard input, and the
STT name is read from *that* input, so guard A's caps can never be satisfied using guard
B's value. Regression tests live in `validators/guard_redteam_test.ak`
(`rt_two_guard_inputs_rejected`, `rt_foreign_utxo_at_guard_addr_rejected`, …).

One **liveness** caveat (not a safety issue): because `expect [guard_in]` is fail-closed,
a third party can grief a pending agent tx by inserting any UTxO at the universal
address. The off-chain tx-builder must never itself include a second guard-address input.
