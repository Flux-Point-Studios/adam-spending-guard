//// Baseline suite for guard v2. Honest within-bounds spends PASS; the core
//// invariants (owner-only sweep, per-tx + daily caps, min-principal, datum-
//// invariance, STT continuity, continuation address) REJECT when violated.
//// The red-team adds the exhaustive adversarial coverage on top of this.

use aiken/interval
use cardano/address
use cardano/assets.{Value}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference, Transaction}
use guard/logic
use guard/types.{AgentSpend, GuardDatum, OwnerSpend, SpendRecord}

const owner_key: ByteArray = #"0000000000000000000000000000000000000000000000000000000a"
const agent_key: ByteArray = #"0000000000000000000000000000000000000000000000000000000b"
const attacker_key: ByteArray = #"0000000000000000000000000000000000000000000000000000000c"
const stt_policy: ByteArray = #"00000000000000000000000000000000000000000000000000000abc"

// Per-guard STT name (in v2 = blake2b of the genesis ref; here any 32-byte value,
// the validator reads it from the input).
const stt_name: ByteArray =
  #"9999999999999999999999999999999999999999999999999999999999999999"

const guard_script: ByteArray =
  #"00000000000000000000000000000000000000000000000000000fff"

const own_tx_id: ByteArray =
  #"1111111111111111111111111111111111111111111111111111111111111111"

fn base_datum() -> GuardDatum {
  GuardDatum {
    owner: owner_key,
    stt_policy,
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
      address: guard_addr(),
      value: guard_value(ada),
      datum: InlineDatum(datum),
      reference_script: None,
    },
  }
}

fn cont_output(datum: GuardDatum, ada: Int) -> Output {
  Output {
    address: guard_addr(),
    value: guard_value(ada),
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

/// Honest agent tx: spend 100 ADA guard paying `outflow`, continue with a fresh
/// record stamped at hi, agent-signed, narrow validity range.
fn honest_tx(outflow: Int) -> Transaction {
  let d = base_datum()
  let hi = 1_000_000_060_000
  let cont_d =
    GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: outflow }] }
  Transaction {
    ..transaction.placeholder,
    inputs: [guard_input(d, 100_000_000)],
    outputs: [cont_output(cont_d, 100_000_000 - outflow)],
    extra_signatories: [agent_key],
    validity_range: interval.between(hi - 60_000, hi),
  }
}

fn agent(tx: Transaction) -> Bool {
  logic.spend_ok(base_datum(), AgentSpend, own_ref(), tx)
}

// ── Honest paths PASS ───────────────────────────────────────────────────────

test honest_within_caps() {
  agent(honest_tx(10_000_000))
}

test honest_exact_per_tx_cap() {
  agent(honest_tx(20_000_000))
}

// ── Owner branch ────────────────────────────────────────────────────────────

test owner_sweep_with_sig() {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(base_datum(), 100_000_000)],
      extra_signatories: [owner_key],
    }
  logic.spend_ok(base_datum(), OwnerSpend, own_ref(), tx)
}

test owner_sweep_without_sig_rejected() fail {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(base_datum(), 100_000_000)],
      extra_signatories: [attacker_key],
    }
  logic.spend_ok(base_datum(), OwnerSpend, own_ref(), tx)
}

// ── Cap + floor + auth rejections ───────────────────────────────────────────

test over_per_tx_cap_rejected() fail {
  agent(honest_tx(20_000_001))
}

test over_daily_cap_rejected() fail {
  let d = base_datum()
  let hi = 1_000_000_060_000
  let r = SpendRecord { at: hi - 1_000, amount: 45_000_000 }
  let start = GuardDatum { ..d, spends: [r] }
  let cont =
    GuardDatum {
      ..start,
      spends: [SpendRecord { at: hi, amount: 10_000_000 }, r],
    }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(start, 100_000_000)],
      outputs: [cont_output(cont, 90_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.between(hi - 60_000, hi),
    }
  logic.spend_ok(start, AgentSpend, own_ref(), tx)
}

test below_min_principal_rejected() fail {
  // continue with only 4 ADA (< min_principal 5 ADA)
  agent(honest_tx(96_000_000))
}

test missing_agent_sig_rejected() fail {
  let d = base_datum()
  let hi = 1_000_000_060_000
  let cont_d =
    GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: 10_000_000 }] }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [cont_output(cont_d, 90_000_000)],
      extra_signatories: [attacker_key],
      validity_range: interval.between(hi - 60_000, hi),
    }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

// ── Datum-invariance: agent cannot retune ───────────────────────────────────

test agent_cannot_raise_caps_rejected() fail {
  let d = base_datum()
  let hi = 1_000_000_060_000
  // continuing datum tries to raise daily_cap
  let cont_d =
    GuardDatum {
      ..d,
      daily_cap: 1_000_000_000,
      spends: [SpendRecord { at: hi, amount: 10_000_000 }],
    }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [cont_output(cont_d, 90_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.between(hi - 60_000, hi),
    }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

test agent_cannot_rotate_owner_rejected() fail {
  let d = base_datum()
  let hi = 1_000_000_060_000
  let cont_d =
    GuardDatum {
      ..d,
      owner: attacker_key,
      spends: [SpendRecord { at: hi, amount: 10_000_000 }],
    }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [cont_output(cont_d, 90_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.between(hi - 60_000, hi),
    }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

// ── Continuation address / STT ──────────────────────────────────────────────

test continuation_to_wrong_address_rejected() fail {
  let d = base_datum()
  let hi = 1_000_000_060_000
  let cont_d =
    GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: 10_000_000 }] }
  // STT-bearing output sent to the attacker, not the guard.
  let bad =
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
      outputs: [bad],
      extra_signatories: [agent_key],
      validity_range: interval.between(hi - 60_000, hi),
    }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

test kill_switch_blocks_agent_rejected() fail {
  let d = GuardDatum { ..base_datum(), kill: True }
  let hi = 1_000_000_060_000
  let cont_d =
    GuardDatum { ..d, spends: [SpendRecord { at: hi, amount: 10_000_000 }] }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [guard_input(d, 100_000_000)],
      outputs: [cont_output(cont_d, 90_000_000)],
      extra_signatories: [agent_key],
      validity_range: interval.between(hi - 60_000, hi),
    }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}
