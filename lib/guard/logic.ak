//// Core spend logic for the ADAM spending-guard v2 (pinnable) + per-asset caps.
//// ADA outflow is metered against per_tx_cap/daily_cap over a sliding window;
//// each owner-declared token is metered the SAME way against its own quantity
//// caps; any undeclared token may be acquired but never leave the guard on the
//// agent branch. No oracle — bounds are owner-set quantities.

use aiken/collection/dict
use aiken/collection/list
use aiken/interval.{Finite}
use cardano/assets.{Value, lovelace_of, quantity_of}
use cardano/transaction.{InlineDatum, OutputReference, Transaction}
use guard/types.{
  AgentSpend, AssetCap, GuardDatum, GuardRedeemer, OwnerSpend, SpendRecord,
}

pub const max_skew: Int = 180_000

pub const max_assets: Int = 20

pub fn spend_ok(
  datum: GuardDatum,
  redeemer: GuardRedeemer,
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  when redeemer is {
    OwnerSpend -> list.has(tx.extra_signatories, datum.owner)
    AgentSpend -> agent_spend_ok(datum, own_ref, tx)
  }
}

fn agent_spend_ok(
  datum: GuardDatum,
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  let agent_signed = list.has(tx.extra_signatories, datum.agent)
  let not_killed = !datum.kill

  expect Some(own_input) = list.find(
    tx.inputs,
    fn(i) { i.output_reference == own_ref },
  )
  let guard_address = own_input.output.address

  expect [Pair(stt_nm, 1)] = own_input.output.value
    |> assets.tokens(datum.stt_policy)
    |> dict.to_pairs()

  let guard_inputs = list.filter(
    tx.inputs,
    fn(i) { i.output.address == guard_address },
  )
  expect [guard_in] = guard_inputs
  expect quantity_of(guard_in.output.value, datum.stt_policy, stt_nm) == 1

  let stt_outputs = list.filter(
    tx.outputs,
    fn(o) { quantity_of(o.value, datum.stt_policy, stt_nm) == 1 },
  )
  expect [cont] = stt_outputs
  let cont_to_guard = cont.address == guard_address

  let assets_ok = list.length(
    assets.flatten(assets.without_lovelace(cont.value)),
  ) <= max_assets

  expect Finite(lo) = tx.validity_range.lower_bound.bound_type
  expect Finite(hi) = tx.validity_range.upper_bound.bound_type
  let range_ok = hi >= lo && hi - lo <= max_skew
  let now = hi
  let not_expired = now < datum.expiry

  // Prune ALL records to the trailing window (shared window_len for ADA + tokens).
  let active = list.filter(
    datum.spends,
    fn(r) { r.at + datum.window_len >= now - max_skew },
  )

  // ── ADA leg (records keyed by policy="" name="") ──
  let ada_out = lovelace_of(cont.value)
  let ada_outflow = lovelace_of(guard_in.output.value) - ada_out
  let ada_per_tx_ok = ada_outflow <= datum.per_tx_cap
  let floor_ok = ada_out >= datum.min_principal
  let ada_daily_ok = sum_active_for(active, #"", #"") + ada_outflow <= datum.daily_cap
  let ada_records = if ada_outflow > 0 {
    [SpendRecord { policy: #"", name: #"", at: now, amount: ada_outflow }]
  } else {
    []
  }

  // ── Declared-token legs (each metered vs its own per_tx/daily quantity caps) ──
  let (tokens_ok, token_records) = meter_tokens(
    datum.token_caps,
    guard_in.output.value,
    cont.value,
    active,
    now,
  )

  // ── Undeclared tokens must be conserved (acquire-only; never leave) ──
  let undeclared_conserved = conserve_undeclared(
    guard_in.output.value,
    cont.value,
    datum.stt_policy,
    datum.token_caps,
  )

  // Canonical new spends: [ADA record] ++ [token records in cap order] ++ active.
  let new_spends = list.concat(list.concat(ada_records, token_records), active)
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
    undeclared_conserved,
    range_ok,
    not_expired,
    ada_per_tx_ok,
    floor_ok,
    ada_daily_ok,
    tokens_ok,
    count_ok,
    datum_ok,
    no_stt_mint,
  }
}

/// Sum the amounts of active records matching (policy, name).
fn sum_active_for(
  records: List<SpendRecord>,
  policy: ByteArray,
  name: ByteArray,
) -> Int {
  list.foldl(
    records,
    0,
    fn(r, acc) {
      if r.policy == policy && r.name == name {
        acc + r.amount
      } else {
        acc
      }
    },
  )
}

/// Meter every declared token: net quantity out <= per_tx and prior-window + out
/// <= daily. Returns (all-ok, new records in cap order for the tokens that left).
fn meter_tokens(
  caps: List<AssetCap>,
  in_val: Value,
  out_val: Value,
  active: List<SpendRecord>,
  now: Int,
) -> (Bool, List<SpendRecord>) {
  list.foldl(
    caps,
    (True, []),
    fn(cap, acc) {
      let (ok, recs) = acc
      let outflow = quantity_of(in_val, cap.policy, cap.name) - quantity_of(
        out_val,
        cap.policy,
        cap.name,
      )
      let per_tx_ok = outflow <= cap.per_tx
      let daily_ok = sum_active_for(active, cap.policy, cap.name) + outflow <= cap.daily
      let recs2 = if outflow > 0 {
        list.concat(
          recs,
          [
            SpendRecord {
              policy: cap.policy,
              name: cap.name,
              at: now,
              amount: outflow,
            },
          ],
        )
      } else {
        recs
      }
      (ok && per_tx_ok && daily_ok, recs2)
    },
  )
}

/// Every non-ADA asset on the guard input that is NEITHER the STT NOR a declared
/// token must remain on the continuation at >= its input quantity (acquire-only).
fn conserve_undeclared(
  in_val: Value,
  out_val: Value,
  stt_policy: ByteArray,
  caps: List<AssetCap>,
) -> Bool {
  list.foldl(
    assets.flatten(assets.without_lovelace(in_val)),
    True,
    fn(triple, acc) {
      let (p, n, q) = triple
      if p == stt_policy || is_declared(caps, p, n) {
        acc
      } else {
        acc && quantity_of(out_val, p, n) >= q
      }
    },
  )
}

fn is_declared(caps: List<AssetCap>, p: ByteArray, n: ByteArray) -> Bool {
  list.any(caps, fn(c) { c.policy == p && c.name == n })
}
