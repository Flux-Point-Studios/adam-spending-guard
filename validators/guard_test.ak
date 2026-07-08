//// Adversarial test suite for the ADAM spending-guard agent branch.
////
//// Assume the agent session key is FULLY COMPROMISED and the attacker crafts
//// arbitrary txs. Every attack must be REJECTED (`fail`); every honest,
//// within-bounds spend must PASS. The daily cap is a TRUE sliding window: net
//// ADA outflow over ANY trailing window_len interval must stay <= daily_cap.

use aiken/builtin
use aiken/interval
use cardano/address
use cardano/assets.{Value}
use cardano/transaction.{Transaction, OutputReference, Input, Output, InlineDatum}
use guard/logic
use guard/types.{GuardDatum, SpendRecord, OwnerSpend, AgentSpend}

// ── Fixtures ────────────────────────────────────────────────────────────────

const owner_key: ByteArray = #"0000000000000000000000000000000000000000000000000000000a"
const agent_key: ByteArray = #"0000000000000000000000000000000000000000000000000000000b"
const attacker_key: ByteArray = #"0000000000000000000000000000000000000000000000000000000c"
const guard_script: ByteArray = #"00000000000000000000000000000000000000000000000000000fff"
const stt_policy: ByteArray = #"00000000000000000000000000000000000000000000000000000abc"
const stt_name: ByteArray = "GUARD"
const own_tx_id: ByteArray = #"1111111111111111111111111111111111111111111111111111111111111111"
const other_tx_id: ByteArray = #"3333333333333333333333333333333333333333333333333333333333333333"
const saturn_pol: ByteArray = #"00000000000000000000000000000000000000000000000000000dad"

fn base_datum() -> GuardDatum {
  GuardDatum {
    agent: agent_key,
    per_tx_cap: 20_000_000,
    daily_cap: 50_000_000,
    window_len: 86_400_000,
    spends: [],
    min_principal: 5_000_000,
    max_spends: 10,
    expiry: 2_000_000_000_000,
    kill: False,
  }
}

fn guard_addr() -> address.Address {
  address.from_script(guard_script)
}

/// Value with `ada` lovelace + one STT.
fn guard_value(ada: Int) -> Value {
  assets.from_lovelace(ada) |> assets.add(stt_policy, stt_name, 1)
}

fn own_ref() -> OutputReference {
  OutputReference { transaction_id: own_tx_id, output_index: 0 }
}

/// Guard input: `ada` + STT + `datum`, at the guard address.
fn guard_input(datum: GuardDatum, ada: Int) -> Input {
  Input {
    output_reference: own_ref(),
    output: Output {
      address: guard_addr(),
      value: guard_value(ada),
      datum: InlineDatum(datum),
      reference_script: None,
    },
  }
}

/// Add `n` distinct dust tokens (under one policy, unique names) to a value.
fn add_dust(v: Value, n: Int) -> Value {
  if n <= 0 {
    v
  } else {
    add_dust(
      assets.add(v, saturn_pol, builtin.integer_to_bytearray(True, 2, n), 1),
      n - 1,
    )
  }
}

/// Continuing output back to the guard with `ada` + STT + `datum`.
fn cont_output(datum: GuardDatum, ada: Int) -> Output {
  Output {
    address: guard_addr(),
    value: guard_value(ada),
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

/// A baseline HONEST agent tx: spend the guard (100 ADA) paying out `outflow`
/// ADA, continuing output = 100-outflow ADA with a single fresh spend record
/// stamped at `now` (= the validity UPPER bound). Signed by the agent.
fn honest_tx(outflow: Int) -> Transaction {
  let d = base_datum()
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  let cont_d = GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: outflow }] }
  Transaction {
    ..transaction.placeholder,
    inputs: [guard_input(d, 100_000_000)],
    outputs: [cont_output(cont_d, 100_000_000 - outflow)],
    extra_signatories: [agent_key],
    validity_range: interval.between(lo, hi),
  }
}

// ── Honest paths PASS ─────────────────────────────────────────────────────

test honest_within_caps() {
  logic.spend_ok(
    owner_key, stt_policy, stt_name, base_datum(), AgentSpend, own_ref(),
    honest_tx(10_000_000),
  )
}

test honest_exact_per_tx_cap() {
  logic.spend_ok(
    owner_key, stt_policy, stt_name, base_datum(), AgentSpend, own_ref(),
    honest_tx(20_000_000),
  )
}

test owner_unrestricted_passes() {
  let tx =
    Transaction { ..transaction.placeholder, extra_signatories: [owner_key] }
  logic.spend_ok(owner_key, stt_policy, stt_name, base_datum(), OwnerSpend, own_ref(), tx)
}

test honest_acquire_token_passes() {
  // A swap BUY — the agent pays ADA (within cap) and the continuing output GAINS
  // a new token. NOTE: this guard bounds ADA outflow ONLY; non-ADA token egress
  // is ALLOWED and UNBOUNDED (that is how selling works). A compromised agent can
  // move the whole non-ADA position out — do NOT park valuable tokens in an
  // agent-spendable guard. See logic.ak agent_spend_ok comment.
  let d = base_datum()
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  let cont_d = GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: 10_000_000 }] }
  let cont =
    Output {
      address: guard_addr(),
      value: guard_value(90_000_000) |> assets.add(saturn_pol, "SATURN", 50),
      datum: InlineDatum(cont_d),
      reference_script: None,
    }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [cont],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

// ── Sliding-window behaviour ──────────────────────────────────────────────

test sliding_multiple_active_within_cap_passes() {
  // Two recent records (20 + 15 = 35) plus a new 10 = 45 <= daily_cap 50.
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  let r1 = SpendRecord { at: hi - 2_000, amount: 20_000_000 }
  let r2 = SpendRecord { at: hi - 1_000, amount: 15_000_000 }
  let d = GuardDatum { ..base_datum(), spends: [r2, r1] }
  let cont_d =
    GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: 10_000_000 }, r2, r1] }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [cont_output(cont_d, 90_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

test sliding_prunes_aged_record_passes() {
  // A 45 ADA record aged fully out of the window is pruned, freeing capacity —
  // a 15 ADA spend that would exceed the cap WITH it succeeds because it is gone.
  let d = base_datum()
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  // aged out only once window_len + max_skew of real time has passed
  let old = SpendRecord { at: hi - d.window_len - logic.max_skew - 1_000, amount: 45_000_000 }
  let d2 = GuardDatum { ..d, spends: [old] }
  let cont_d = GuardDatum { ..d2, spends: [SpendRecord { at: hi, amount: 15_000_000 }] }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d2, 100_000_000)],
      outputs: [cont_output(cont_d, 85_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d2, AgentSpend, own_ref(), tx)
}

// ── Attacks FAIL ───────────────────────────────────────────────────────────

test attack_over_per_tx_cap() fail {
  logic.spend_ok(
    owner_key, stt_policy, stt_name, base_datum(), AgentSpend, own_ref(),
    honest_tx(20_000_001),
  )
}

test attack_sliding_over_daily_cap() fail {
  // A recent 40 ADA record is still active; +20 pushes the rolling sum to 60 > 50.
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  let recent = SpendRecord { at: hi - 1_000, amount: 40_000_000 }
  let d = GuardDatum { ..base_datum(), spends: [recent] }
  let cont_d =
    GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: 20_000_000 }, recent] }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [cont_output(cont_d, 80_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

test attack_boundary_burst_blocked() fail {
  // THE <=1x proof: the exact burst a tumbling window allowed — 45 spent moments
  // ago, then 15 more seconds later. Both records are inside the trailing window,
  // so the rolling sum 45+15=60 > 50 is REJECTED. No boundary reset exists.
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  let recent = SpendRecord { at: hi - 500, amount: 45_000_000 }
  let d = GuardDatum { ..base_datum(), spends: [recent] }
  let cont_d =
    GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: 15_000_000 }, recent] }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [cont_output(cont_d, 85_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

test attack_forge_spends_reset() fail {
  // Attacker drops the active record from the continuing datum to reset the
  // accumulator. The validator recomputes the expected list ⇒ datum_ok fails
  // (the rolling sum here, 40+10=50, is itself within cap — only the forge trips).
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  let recent = SpendRecord { at: hi - 500, amount: 40_000_000 }
  let d = GuardDatum { ..base_datum(), spends: [recent] }
  let cont_d = GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: 10_000_000 }] }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [cont_output(cont_d, 90_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

test attack_exceed_max_spends() fail {
  // Two dust records already fill max_spends=2 (sum within cap); an 11th-style
  // record would exceed the list bound.
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  let r1 = SpendRecord { at: hi - 2_000, amount: 1_000_000 }
  let r2 = SpendRecord { at: hi - 1_000, amount: 1_000_000 }
  let d = GuardDatum { ..base_datum(), max_spends: 2, spends: [r2, r1] }
  let cont_d =
    GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: 1_000_000 }, r2, r1] }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [cont_output(cont_d, 99_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

test attack_dust_bloat_dos() fail {
  // Red-team finding: a compromised agent accretes distinct dust tokens into the
  // continuing output across many txs until the UTxO exceeds the ledger value-size
  // limit and becomes unspendable (bricking even the owner sweep). The distinct-
  // asset cap rejects a continuing output carrying too many tokens.
  let d = base_datum()
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  let cont_d = GuardDatum { ..d, spends: [] }
  let cont =
    Output {
      address: guard_addr(),
      value: add_dust(guard_value(100_000_000), 25),
      datum: InlineDatum(cont_d),
      reference_script: None,
    }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [cont],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

test attack_window_len_apart_burst_blocked() fail {
  // max_skew timestamp abuse: a prior 40-ADA record stamped so that
  // record.at + window_len == now - max_skew exactly. A naive strict prune at
  // `now` would drop it (allowing 15 more = a 2x burst over a window_len
  // interval); the skew-adjusted, boundary-inclusive prune keeps it active, so
  // the attacker's continuing datum (which omits it) fails datum_ok.
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  let d0 = base_datum()
  let at1 = hi - logic.max_skew - d0.window_len
  let recent = SpendRecord { at: at1, amount: 40_000_000 }
  let d = GuardDatum { ..d0, spends: [recent] }
  let cont_d = GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: 15_000_000 }] }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [cont_output(cont_d, 85_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

test attack_no_agent_signature() fail {
  let tx = Transaction { ..honest_tx(10_000_000), extra_signatories: [attacker_key] }
  logic.spend_ok(owner_key, stt_policy, stt_name, base_datum(), AgentSpend, own_ref(), tx)
}

test attack_kill_switch_on() fail {
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  let d = GuardDatum { ..base_datum(), kill: True }
  let cont_d = GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: 10_000_000 }] }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [cont_output(cont_d, 90_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

test attack_expired_session() fail {
  let d = base_datum()
  let lo = 2_000_000_050_000
  let hi = lo + 60_000
  let cont_d = GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: 10_000_000 }] }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [cont_output(cont_d, 90_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

test attack_expiry_skew_bypass() fail {
  // Real time is past hard expiry, but the agent sets the LOWER bound just under
  // it. The deadline uses the UPPER bound (now = hi >= expiry), so it is rejected.
  let e = 2_000_000_000_000
  let d = base_datum()
  let lo = e - 1
  let hi = lo + 180_000
  let cont_d = GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: 10_000_000 }] }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [cont_output(cont_d, 90_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

test attack_raise_own_cap() fail {
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  let d = base_datum()
  let cont_d =
    GuardDatum {
      ..d,
      per_tx_cap: 999_000_000,
      spends: [SpendRecord { at: hi, amount: 10_000_000 }],
    }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [cont_output(cont_d, 90_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

test attack_laundering_to_attacker_address() fail {
  // The continuing (STT-bearing) output goes to the ATTACKER, not the guard.
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  let d = base_datum()
  let cont_d = GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: 10_000_000 }] }
  let attacker_out =
    Output {
      address: address.from_verification_key(attacker_key),
      value: guard_value(90_000_000),
      datum: InlineDatum(cont_d),
      reference_script: None,
    }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [attacker_out],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

test sell_token_for_ada_passes() {
  // Autonomous SELL: the guard holds 500 SATURN; the agent sells them, ADA comes
  // back into the continuing output (a gain, outflow < 0). Token egress is
  // allowed — the bound is on ADA, and the STT stays at the guard.
  let d = base_datum()
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  let in_val = guard_value(100_000_000) |> assets.add(saturn_pol, "SATURN", 500)
  let guard_in =
    Input {
      output_reference: own_ref(),
      output: Output {
        address: guard_addr(),
        value: in_val,
        datum: InlineDatum(d),
        reference_script: None,
      },
    }
  // sold 500 SATURN for 8 ADA — cont keeps the STT, gains ADA, no SATURN.
  let cont_d = GuardDatum { ..d, spends: [] }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_in],
      outputs: [cont_output(cont_d, 108_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

test attack_sell_cannot_strand_stt() fail {
  // A sell must still keep the STT at the guard: moving the STT out with the
  // tokens (no STT-bearing guard output) is rejected.
  let d = base_datum()
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  let in_val = guard_value(100_000_000) |> assets.add(saturn_pol, "SATURN", 500)
  let guard_in =
    Input {
      output_reference: own_ref(),
      output: Output {
        address: guard_addr(),
        value: in_val,
        datum: InlineDatum(d),
        reference_script: None,
      },
    }
  // everything (incl. the STT) leaves to the attacker; no continuing STT output.
  let attacker_out =
    Output {
      address: address.from_verification_key(attacker_key),
      value: guard_value(100_000_000) |> assets.add(saturn_pol, "SATURN", 500),
      datum: transaction.NoDatum,
      reference_script: None,
    }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_in],
      outputs: [attacker_out],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

test attack_double_satisfaction() fail {
  // Two UTxOs at the guard address (one without the STT) share a single
  // continuing output. Reject: exactly one guard input.
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  let d = base_datum()
  let g_in = guard_input(d, 100_000_000)
  let p_in =
    Input {
      output_reference: OutputReference { transaction_id: other_tx_id, output_index: 0 },
      output: Output {
        address: guard_addr(),
        value: assets.from_lovelace(100_000_000),
        datum: InlineDatum(d),
        reference_script: None,
      },
    }
  let cont_d = GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: 20_000_000 }] }
  let attacker_out =
    Output {
      address: address.from_verification_key(attacker_key),
      value: assets.from_lovelace(120_000_000),
      datum: transaction.NoDatum,
      reference_script: None,
    }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [g_in, p_in],
      outputs: [cont_output(cont_d, 80_000_000), attacker_out],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

test attack_unbounded_validity_range() fail {
  let d = base_datum()
  let cont_d = GuardDatum { ..d, spends: [SpendRecord { at: 0, amount: 10_000_000 }] }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [cont_output(cont_d, 90_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.everything,
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

test attack_below_min_principal() fail {
  let d = base_datum()
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  let cont_d = GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: 20_000_000 }] }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 22_000_000)],
      outputs: [cont_output(cont_d, 2_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}

test attack_no_continuing_output() fail {
  let d = base_datum()
  let lo = 1_000_000_050_000
  let hi = lo + 60_000
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [
        Output {
          address: address.from_verification_key(attacker_key),
          value: assets.from_lovelace(90_000_000),
          datum: transaction.NoDatum,
          reference_script: None,
        },
      ],
      extra_signatories: [agent_key],
      validity_range: interval.between(lo, hi),
    }
  logic.spend_ok(owner_key, stt_policy, stt_name, d, AgentSpend, own_ref(), tx)
}
