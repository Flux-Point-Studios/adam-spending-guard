//// Core spend logic for the ADAM spending-guard, factored out so both the
//// validator and the adversarial test suite exercise the exact same code.
//// See validators/guard.ak for the security narrative.

use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use aiken/interval.{Finite}
use cardano/assets.{AssetName, PolicyId, lovelace_of, quantity_of}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference, Transaction}
use guard/types.{
  AgentSpend, GuardDatum, GuardRedeemer, OwnerSpend, SpendRecord,
}

/// Max width of the tx validity range (ms).
pub const max_skew: Int = 180_000

/// Max distinct non-ADA assets (incl. the STT) the continuing output may carry.
/// Caps the guard UTxO value size so a compromised agent cannot accrete dust
/// tokens until the UTxO exceeds the ledger size limit and becomes unspendable.
pub const max_assets: Int = 20

/// Top-level guard decision (owner branch unrestricted; agent branch bounded).
pub fn spend_ok(
  owner: VerificationKeyHash,
  stt_policy: PolicyId,
  stt_name: AssetName,
  datum: GuardDatum,
  redeemer: GuardRedeemer,
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  when redeemer is {
    OwnerSpend -> list.has(tx.extra_signatories, owner)
    AgentSpend -> agent_spend_ok(datum, own_ref, tx, stt_policy, stt_name)
  }
}

fn agent_spend_ok(
  datum: GuardDatum,
  own_ref: OutputReference,
  tx: Transaction,
  stt_policy: PolicyId,
  stt_name: AssetName,
) -> Bool {
  let agent_signed = list.has(tx.extra_signatories, datum.agent)
  let not_killed = !datum.kill

  expect Some(own_input) =
    list.find(tx.inputs, fn(i) { i.output_reference == own_ref })
  let guard_address = own_input.output.address

  // Exactly ONE input sits at the guard address and it carries the STT. This
  // binds all accounting to the singleton and kills double-satisfaction: a
  // second guard-address UTxO cannot ride along to skim value while the
  // per-input outflow is charged only once against the accumulator.
  let guard_inputs =
    list.filter(tx.inputs, fn(i) { i.output.address == guard_address })
  expect [guard_in] = guard_inputs
  expect quantity_of(guard_in.output.value, stt_policy, stt_name) == 1

  // The single STT-bearing output is the continuing guard UTxO.
  let stt_outputs =
    list.filter(
      tx.outputs,
      fn(o) { quantity_of(o.value, stt_policy, stt_name) == 1 },
    )
  expect [cont] = stt_outputs
  let cont_to_guard = cont.address == guard_address

  // Tokens may LEAVE on the agent branch (that IS selling on a DEX) — the bound
  // is on ADA only. Every lovelace that leaves the guard is captured by
  // `outflow = lovelace_in - lovelace_out` below (whether it goes to a maker
  // payment, a fee, a premium, or rides out as min-ADA on a departing token), so
  // the agent can bleed at most per_tx_cap / daily_cap ADA regardless of how the
  // tokens flow. The STT singleton + guard-address continuing output are still
  // enforced above, so the guard's authenticated UTxO cannot be stolen; agent-
  // acquired position appreciation is knowingly at risk (see design notes).
  //
  // Bound the distinct-asset count so the guard UTxO cannot be dust-bloated past
  // the ledger value-size limit (which would brick even the owner sweep).
  let assets_ok =
    list.length(assets.flatten(assets.without_lovelace(cont.value))) <= max_assets

  expect Finite(lo) = tx.validity_range.lower_bound.bound_type
  expect Finite(hi) = tx.validity_range.upper_bound.bound_type
  let range_ok = hi >= lo && hi - lo <= max_skew
  // Drive both the hard deadline AND the window clock from the UPPER bound: hi
  // is >= the real inclusion slot, so a spend can never be charged into an
  // already-elapsed window (which `now = lo` allowed, leaking up to 3x across a
  // boundary). This restores the clean <= 2x-per-window residual.
  let now = hi
  let not_expired = now < datum.expiry

  let ada_in = lovelace_of(guard_in.output.value)
  let ada_out = lovelace_of(cont.value)
  // Net ADA leaving the guard. Negative when ADA flows IN (a sell / realised
  // gain), which is always allowed — only OUTflow is capped.
  let outflow = ada_in - ada_out
  let per_tx_ok = outflow <= datum.per_tx_cap
  let floor_ok = ada_out >= datum.min_principal

  // True sliding window: keep only the outflow records still inside the trailing
  // window_len, and require their sum plus this outflow to stay within daily_cap.
  // A record's `at` is stamped at `now` (= hi, up to max_skew ahead of the real
  // slot), and `now` here may likewise lead real time by max_skew — so the prune
  // is boundary-inclusive and shifted by max_skew. A record therefore cannot be
  // dropped until window_len of REAL time has definitely elapsed, giving a tight
  // net-ADA bound of <= daily_cap over ANY real-time window_len interval.
  let active =
    list.filter(
      datum.spends,
      fn(r) { r.at + datum.window_len >= now - max_skew },
    )
  let sum_active = list.foldl(active, 0, fn(r, acc) { acc + r.amount })
  let daily_ok = sum_active + outflow <= datum.daily_cap

  // Record this outflow (skip zero-ADA spends so token-only moves don't bloat
  // the list). The list is bounded by max_spends to cap datum growth.
  let new_spends =
    if outflow > 0 {
      [SpendRecord { at: now, amount: outflow }, ..active]
    } else {
      active
    }
  let count_ok = list.length(new_spends) <= datum.max_spends

  let expected_datum = GuardDatum { ..datum, spends: new_spends }
  expect InlineDatum(cont_datum_data) = cont.datum
  expect cont_datum: GuardDatum = cont_datum_data
  let datum_ok = cont_datum == expected_datum

  let no_stt_mint = quantity_of(tx.mint, stt_policy, stt_name) == 0

  and {
    agent_signed,
    not_killed,
    cont_to_guard,
    assets_ok,
    range_ok,
    not_expired,
    per_tx_ok,
    floor_ok,
    daily_ok,
    count_ok,
    datum_ok,
    no_stt_mint,
  }
}
