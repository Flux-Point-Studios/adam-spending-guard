//// Core spend logic for the ADAM spending-guard v2 (pinnable) + per-asset caps.
//// ADA outflow is metered against per_tx_cap/daily_cap over a sliding window;
//// each owner-declared token is metered the SAME way against its own quantity
//// caps; any undeclared token may be acquired but never leave the guard on the
//// agent branch. No oracle — bounds are owner-set quantities.
////
//// The guard validator is also its own state-token policy, so the policy id is
//// the guard's script hash. A state token only ever sits in an output that
//// `guard_output` admits: the mint opens one, an owner spend either burns the
//// token or continues the guard under the same rules, and the agent branch keeps
//// the datum.

use aiken/cbor
use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{blake2b_256}
use aiken/interval.{Finite}
use cardano/address.{Script}
use cardano/assets.{AssetName, PolicyId, Value, lovelace_of, quantity_of}
use cardano/transaction.{InlineDatum, Output, OutputReference, Transaction}
use guard/types.{
  AgentSpend, AssetCap, GuardDatum, GuardRedeemer, OwnerSpend, SpendRecord,
}

pub const max_skew: Int = 180_000

pub const max_assets: Int = 20

/// One hour. A shorter window prunes records within minutes of stamping them,
/// which lets the agent spend the whole daily_cap again and again.
pub const min_window_len: Int = 3_600_000

/// Thirty days.
pub const max_window_len: Int = 2_592_000_000

/// Bound max_spends and token_caps so the heaviest agent spend leaves room in
/// the per-transaction budget for the swap scripts that run beside it.
pub const max_spend_records: Int = 50

pub const max_token_caps: Int = 10

pub fn spend_ok(
  datum: GuardDatum,
  redeemer: GuardRedeemer,
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  expect Some(own_input) = list.find(
    tx.inputs,
    fn(i) { i.output_reference == own_ref },
  )
  expect Script(policy) = own_input.output.address.payment_credential
  when redeemer is {
    OwnerSpend -> owner_spend_ok(datum, own_input.output, policy, tx)
    AgentSpend -> agent_spend_ok(datum, own_input.output, policy, tx)
  }
}

/// The owner signs. Every state token on the spent output is either burned or
/// continued into a guard `guard_output` admits, with the spend records carried
/// forward. Nothing else in the datum is read, so an output without a state
/// token is the owner's to sweep whatever the rest of its datum holds.
fn owner_spend_ok(
  datum: GuardDatum,
  own_output: Output,
  policy: PolicyId,
  tx: Transaction,
) -> Bool {
  list.has(tx.extra_signatories, datum.owner) && list.all(
    dict.keys(assets.tokens(own_output.value, policy)),
    fn(name) {
      quantity_of(tx.mint, policy, name) < 0 || guard_output(policy, name, tx).spends == datum.spends
    },
  )
}

/// Mint opens a guard: the name is one-shot and the token lands in a guard with
/// no spend records that is not killed. Burn checks nothing else, so closing a
/// guard never depends on its state.
pub fn mint_ok(policy: PolicyId, tx: Transaction) -> Bool {
  expect [Pair(name, amount)] = tx.mint
    |> assets.tokens(policy)
    |> dict.to_pairs()
  when amount is {
    1 -> and {
        list.any(
          tx.inputs,
          fn(i) { blake2b_256(cbor.serialise(i.output_reference)) == name },
        ),
        {
          let opened = guard_output(policy, name, tx)
          opened.spends == [] && !opened.kill
        },
      }
    -1 -> True
    _ -> False
  }
}

/// The one output carrying state token `name`, required to be a guard: at the
/// guard script (any stake credential), no reference script, this token alone
/// under the policy, at most `max_assets` non-ADA assets, at least
/// `min_principal` lovelace, an inline datum naming this policy on admissible
/// terms, and signed by that datum's owner. Returns the datum.
fn guard_output(
  policy: PolicyId,
  name: AssetName,
  tx: Transaction,
) -> GuardDatum {
  expect [out] = list.filter(
    tx.outputs,
    fn(o) { quantity_of(o.value, policy, name) > 0 },
  )
  expect InlineDatum(raw) = out.datum
  expect datum: GuardDatum = raw
  expect and {
      out.address.payment_credential == Script(policy),
      out.reference_script == None,
      dict.to_pairs(assets.tokens(out.value, policy)) == [Pair(name, 1)],
      list.length(assets.flatten(assets.without_lovelace(out.value))) <= max_assets,
      lovelace_of(out.value) >= datum.min_principal,
      datum.stt_policy == policy,
      terms_ok(datum),
      list.has(tx.extra_signatories, datum.owner),
    }
  datum
}

fn agent_spend_ok(
  datum: GuardDatum,
  own_output: Output,
  policy: PolicyId,
  tx: Transaction,
) -> Bool {
  let agent_signed = list.has(tx.extra_signatories, datum.agent)
  let not_killed = !datum.kill
  let guard_address = own_output.address

  expect [Pair(stt_nm, 1)] = own_output.value
    |> assets.tokens(policy)
    |> dict.to_pairs()

  let guard_inputs = list.filter(
    tx.inputs,
    fn(i) { i.output.address == guard_address },
  )
  expect [guard_in] = guard_inputs
  expect quantity_of(guard_in.output.value, policy, stt_nm) == 1

  let stt_outputs = list.filter(
    tx.outputs,
    fn(o) { quantity_of(o.value, policy, stt_nm) == 1 },
  )
  expect [cont] = stt_outputs
  let cont_to_guard = cont.address == guard_address
  let stt_singleton = dict.to_pairs(assets.tokens(cont.value, policy)) == [
    Pair(stt_nm, 1),
  ]
  let no_ref_script = cont.reference_script == None

  // Every output that receives the state token already meets these terms; the
  // agent branch re-checks them so a negative record or short window never runs.
  let state_ok = terms_ok(datum) && list.all(
    datum.spends,
    fn(r) { r.amount > 0 },
  )

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
    policy,
    datum.token_caps,
  )

  // Canonical new spends: [ADA record] ++ [token records in cap order] ++ active.
  let new_spends = list.concat(list.concat(ada_records, token_records), active)
  let count_ok = list.length(new_spends) <= datum.max_spends

  let expected_datum = GuardDatum { ..datum, spends: new_spends }
  expect InlineDatum(cont_datum_data) = cont.datum
  expect cont_datum: GuardDatum = cont_datum_data
  let datum_ok = cont_datum == expected_datum

  let no_stt_mint = quantity_of(tx.mint, policy, stt_nm) == 0

  and {
    agent_signed,
    not_killed,
    state_ok,
    cont_to_guard,
    stt_singleton,
    no_ref_script,
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

/// The caps, window and bounds a guard may run under: checked whenever a state
/// token lands in a guard output and by the agent branch on every spend.
pub fn terms_ok(datum: GuardDatum) -> Bool {
  and {
    datum.window_len >= min_window_len,
    datum.window_len <= max_window_len,
    datum.per_tx_cap > 0,
    datum.per_tx_cap <= datum.daily_cap,
    datum.min_principal >= 0,
    datum.max_spends > 0,
    datum.max_spends <= max_spend_records,
    list.length(datum.token_caps) <= max_token_caps,
    list.all(datum.token_caps, fn(c) { c.per_tx > 0 && c.per_tx <= c.daily }),
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
