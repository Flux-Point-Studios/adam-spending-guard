//// Core spend logic for the ADAM spending-guard v2 (pinnable: no script params;
//// owner + stt_policy live in the datum). Factored out so the validator and the
//// adversarial tests exercise identical code.

use aiken/collection/dict
use aiken/collection/list
use aiken/interval.{Finite}
use cardano/assets.{lovelace_of, quantity_of}
use cardano/transaction.{InlineDatum, OutputReference, Transaction}
use guard/types.{AgentSpend, GuardDatum, GuardRedeemer, OwnerSpend, SpendRecord}

pub const max_skew: Int = 180_000

pub const max_assets: Int = 20

pub fn spend_ok(
  datum: GuardDatum,
  redeemer: GuardRedeemer,
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  when redeemer is {
    // Unrestricted root branch — owner (from the datum) signs.
    OwnerSpend -> list.has(tx.extra_signatories, datum.owner)
    AgentSpend -> agent_spend_ok(datum, own_ref, tx)
  }
}

fn agent_spend_ok(datum: GuardDatum, own_ref: OutputReference, tx: Transaction) -> Bool {
  let agent_signed = list.has(tx.extra_signatories, datum.agent)
  let not_killed = !datum.kill

  expect Some(own_input) =
    list.find(tx.inputs, fn(i) { i.output_reference == own_ref })
  let guard_address = own_input.output.address

  // The STT authenticating THIS guard: policy from the datum, name read from the
  // spent UTxO (per-guard, = blake2b of its genesis). Exactly one such asset.
  expect [Pair(stt_nm, 1)] =
    own_input.output.value |> assets.tokens(datum.stt_policy) |> dict.to_pairs()

  // Exactly ONE input at the guard address, carrying the STT — binds accounting
  // to the singleton and kills double-satisfaction (a shared universal address
  // still isolates guards because a second guard input trips this `expect`).
  let guard_inputs =
    list.filter(tx.inputs, fn(i) { i.output.address == guard_address })
  expect [guard_in] = guard_inputs
  expect quantity_of(guard_in.output.value, datum.stt_policy, stt_nm) == 1

  // The single STT-bearing output = the continuing guard UTxO, back to guard.
  let stt_outputs =
    list.filter(
      tx.outputs,
      fn(o) { quantity_of(o.value, datum.stt_policy, stt_nm) == 1 },
    )
  expect [cont] = stt_outputs
  let cont_to_guard = cont.address == guard_address

  let assets_ok =
    list.length(assets.flatten(assets.without_lovelace(cont.value))) <= max_assets

  // TOKEN CONSERVATION: every native asset on the guard INPUT must remain on the
  // continuing output at >= its input quantity. The agent may only ACQUIRE tokens
  // (a buy: ADA out, token in) — it can never move tokens OUT of the guard. This
  // closes native-token exfiltration, which the lovelace-only `outflow` below
  // does not see (a compromised agent could otherwise ship the guard's tokens
  // out for free with outflow = 0). Realising a token position (token -> ADA) is
  // deliberately an OWNER action, not on the bounded agent branch.
  let non_ada_conserved =
    list.foldl(
      assets.flatten(assets.without_lovelace(guard_in.output.value)),
      True,
      fn(triple, acc) {
        let (p, n, q) = triple
        acc && quantity_of(cont.value, p, n) >= q
      },
    )

  expect Finite(lo) = tx.validity_range.lower_bound.bound_type
  expect Finite(hi) = tx.validity_range.upper_bound.bound_type
  let range_ok = hi >= lo && hi - lo <= max_skew
  let now = hi
  let not_expired = now < datum.expiry

  let ada_in = lovelace_of(guard_in.output.value)
  let ada_out = lovelace_of(cont.value)
  let outflow = ada_in - ada_out
  let per_tx_ok = outflow <= datum.per_tx_cap
  let floor_ok = ada_out >= datum.min_principal

  let active =
    list.filter(
      datum.spends,
      fn(r) { r.at + datum.window_len >= now - max_skew },
    )
  let sum_active = list.foldl(active, 0, fn(r, acc) { acc + r.amount })
  let daily_ok = sum_active + outflow <= datum.daily_cap

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

  let no_stt_mint = quantity_of(tx.mint, datum.stt_policy, stt_nm) == 0

  and {
    agent_signed,
    not_killed,
    cont_to_guard,
    assets_ok,
    non_ada_conserved,
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
