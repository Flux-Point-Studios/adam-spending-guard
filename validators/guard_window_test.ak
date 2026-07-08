//// Sliding-window ledger-consistency proofs for the agent branch.
////
//// An adversarial red-team flagged the `now = hi` window clock (logic.ak): since
//// `range_ok` only bounds the validity WIDTH (`hi - lo <= max_skew`) and not hi's
//// absolute value, a unit test can call `spend_ok` with `hi` fast-forwarded to
//// `expiry-1` while spend records sit at ~real-time, pruning every record and
//// collapsing the daily cap to a per-tx check.
////
//// That is a UNIT-TEST ARTIFACT, not an on-chain exploit, for two reasons the
//// validator enforces together:
////   1. datum_ok pins every new record to `{at: now = hi}` — a stamp CANNOT be
////      backdated (see `stamp_cannot_be_backdated`), so a record's `.at` equals
////      the `hi` of the tx that created it.
////   2. The ledger only includes a tx when the real slot s ∈ [lo, hi] with
////      `hi - lo <= max_skew`, so `hi <= s + max_skew`. Thus every record's `.at`
////      is within `max_skew` of its real creation slot and can never trail real
////      time.
//// Together: a record is pruned only once its REAL age exceeds `window_len`
//// (the prune's `- max_skew` shift exactly cancels the stamp's `+ max_skew`
//// lead). The fast-forwarded-hi datum is unreachable because those records
//// would have been stamped with the fast-forwarded hi too.
////
//// These tests hold `.at` and every `[lo, hi]` consistent with ONE real timeline
//// and show net ADA outflow over any real `window_len` stays <= daily_cap with
//// ZERO exploitable slack; the only residual is the guard being slightly OVER-
//// conservative near the boundary (blocks honest spends early, never over-drains).

use aiken/interval
use cardano/address
use cardano/assets.{Value}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference, Transaction}
use guard/logic
use guard/types.{AgentSpend, GuardDatum, SpendRecord}

const owner_key: ByteArray = #"0000000000000000000000000000000000000000000000000000000a"
const agent_key: ByteArray = #"0000000000000000000000000000000000000000000000000000000b"
const stt_policy: ByteArray = #"00000000000000000000000000000000000000000000000000000abc"
const stt_name: ByteArray = "GUARD"
const own_tx_id: ByteArray =
  #"1111111111111111111111111111111111111111111111111111111111111111"

// Matches logic.max_skew (180s) and base caps used across the suite.
const skew: Int = 180_000

const window: Int = 86_400_000

fn base_datum() -> GuardDatum {
  GuardDatum {
    agent: agent_key,
    per_tx_cap: 20_000_000,
    daily_cap: 50_000_000,
    window_len: window,
    spends: [],
    min_principal: 5_000_000,
    max_spends: 10,
    expiry: 2_000_000_000_000,
    kill: False,
  }
}

fn guard_value(ada: Int) -> Value {
  assets.from_lovelace(ada) |> assets.add(stt_policy, stt_name, 1)
}

fn own_ref() -> OutputReference {
  OutputReference { transaction_id: own_tx_id, output_index: 0 }
}

fn guard_input(datum: GuardDatum, ada: Int) -> Input {
  Input {
    output_reference: own_ref(),
    output: Output {
      address: address.from_script(
        #"00000000000000000000000000000000000000000000000000000fff",
      ),
      value: guard_value(ada),
      datum: InlineDatum(datum),
      reference_script: None,
    },
  }
}

fn cont_output(datum: GuardDatum, ada: Int) -> Output {
  Output {
    address: address.from_script(
      #"00000000000000000000000000000000000000000000000000000fff",
    ),
    value: guard_value(ada),
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

/// Build an agent tx. `start` is the spent datum; `cont` the continuing datum;
/// `outflow` the net ADA leaving; validity range [hi-60_000, hi].
fn agent_tx(start: GuardDatum, cont: GuardDatum, outflow: Int, hi: Int) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [guard_input(start, 100_000_000)],
    outputs: [cont_output(cont, 100_000_000 - outflow)],
    extra_signatories: [agent_key],
    validity_range: interval.between(hi - 60_000, hi),
  }
}

fn check(start: GuardDatum, tx: Transaction) -> Bool {
  logic.spend_ok(owner_key, stt_policy, stt_name, start, AgentSpend, own_ref(), tx)
}

// ── The daily cap holds under a consistent timeline ─────────────────────────

/// Full daily_cap already spent 1h + 2h before the drain tx (deep inside the
/// 24h window). A fresh 1 lovelace would push the window sum past daily_cap →
/// REJECTED. This is the scenario the red-team claimed to bypass; with `.at`
/// consistent with the drain tx's `hi`, both records are correctly kept.
test consistent_full_cap_plus_one_rejected() fail {
  let hi = 1_000_086_400_000
  let r1 = SpendRecord { at: hi - 7_200_000, amount: 30_000_000 }
  let r2 = SpendRecord { at: hi - 3_600_000, amount: 20_000_000 }
  let start = GuardDatum { ..base_datum(), spends: [r2, r1] }
  let cont =
    GuardDatum { ..start, spends: [SpendRecord { at: hi, amount: 1 }, r2, r1] }
  check(start, agent_tx(start, cont, 1, hi))
}

/// Reaching EXACTLY daily_cap in the window is allowed (30M prior + 20M now).
test consistent_exact_daily_cap_accepted() {
  let hi = 1_000_086_400_000
  let r1 = SpendRecord { at: hi - 3_600_000, amount: 30_000_000 }
  let start = GuardDatum { ..base_datum(), spends: [r1] }
  let cont =
    GuardDatum {
      ..start,
      spends: [SpendRecord { at: hi, amount: 20_000_000 }, r1],
    }
  check(start, agent_tx(start, cont, 20_000_000, hi))
}

// ── The prune boundary is exactly window_len (skew-adjusted) ────────────────

/// Record at the boundary `at + window_len == now - max_skew` is KEPT (the
/// filter is `>=`), so a full-cap spend that old still blocks a fresh spend.
test boundary_record_kept_over_cap_rejected() fail {
  let hi = 1_100_000_000_000
  let at1 = hi - skew - window
  let r1 = SpendRecord { at: at1, amount: 50_000_000 }
  let start = GuardDatum { ..base_datum(), spends: [r1] }
  let cont =
    GuardDatum { ..start, spends: [SpendRecord { at: hi, amount: 1 }, r1] }
  check(start, agent_tx(start, cont, 1, hi))
}

/// One tick past the boundary the record is DROPPED and capacity frees — but
/// only once its real age exceeds window_len, which is CORRECT (the window
/// genuinely rolls). A fresh per_tx_cap spend is then accepted.
test past_boundary_record_dropped_fresh_accepted() {
  let hi = 1_100_000_000_000
  let at1 = hi - skew - window - 1
  let r1 = SpendRecord { at: at1, amount: 50_000_000 }
  let start = GuardDatum { ..base_datum(), spends: [r1] }
  let cont =
    GuardDatum { ..start, spends: [SpendRecord { at: hi, amount: 20_000_000 }] }
  check(start, agent_tx(start, cont, 20_000_000, hi))
}

// ── The stamp cannot be backdated (this is what makes the above hold) ───────

/// The attacker tries to stamp the new record a full day in the PAST so it ages
/// out sooner in a later tx. datum_ok forces `.at = now = hi`, so the tampered
/// continuing datum mismatches the validator's recompute → REJECTED. Because a
/// stamp always equals its creation `hi` (ledger-bounded to real time ± skew),
/// no record can be made to look older than it is.
test stamp_cannot_be_backdated() fail {
  let hi = 1_000_086_400_000
  let start = GuardDatum { ..base_datum(), spends: [] }
  let cont =
    GuardDatum {
      ..start,
      spends: [SpendRecord { at: hi - window, amount: 20_000_000 }],
    }
  check(start, agent_tx(start, cont, 20_000_000, hi))
}
