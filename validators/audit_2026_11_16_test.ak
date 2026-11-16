//// Pre-mainnet audit, 2026-11-16. Each `fail` test is a transaction the
//// deployed guard accepted and must now reject; the plain tests are the honest
//// twins that must keep passing.

use aiken/interval
use cardano/address
use cardano/assets.{Value}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction,
}
use guard/logic
use guard/types.{AgentSpend, AssetCap, GuardDatum, OwnerSpend, SpendRecord}

const owner_key: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000a"

const agent_key: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000b"

const stt_policy: ByteArray =
  #"00000000000000000000000000000000000000000000000000000abc"

const stt_name: ByteArray =
  #"9999999999999999999999999999999999999999999999999999999999999999"

const other_stt_name: ByteArray =
  #"8888888888888888888888888888888888888888888888888888888888888888"

const tok_pol: ByteArray =
  #"00000000000000000000000000000000000000000000000000001111"

const tok_name: ByteArray = "TKN"

const guard_script: ByteArray =
  #"00000000000000000000000000000000000000000000000000000fff"

const own_tx_id: ByteArray =
  #"1111111111111111111111111111111111111111111111111111111111111111"

const hi: Int = 1_000_000_060_000

fn base_datum() -> GuardDatum {
  GuardDatum {
    owner: owner_key,
    stt_policy,
    agent: agent_key,
    per_tx_cap: 20_000_000,
    daily_cap: 50_000_000,
    window_len: 86_400_000,
    token_caps: [
      AssetCap { policy: tok_pol, name: tok_name, per_tx: 500, daily: 1000 },
    ],
    spends: [],
    min_principal: 5_000_000,
    max_spends: 10,
    expiry: 2_000_000_000_000,
    kill: False,
  }
}

fn v_base(ada: Int) -> Value {
  assets.from_lovelace(ada) |> assets.add(stt_policy, stt_name, 1)
}

fn own_ref() -> OutputReference {
  OutputReference { transaction_id: own_tx_id, output_index: 0 }
}

fn guard_in(v: Value, d: GuardDatum) -> Input {
  Input {
    output_reference: own_ref(),
    output: Output {
      address: address.from_script(guard_script),
      value: v,
      datum: InlineDatum(d),
      reference_script: None,
    },
  }
}

fn cont(v: Value, d: GuardDatum) -> Output {
  Output {
    address: address.from_script(guard_script),
    value: v,
    datum: InlineDatum(d),
    reference_script: None,
  }
}

fn agent_tx(inp: Input, out: Output) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [inp],
    outputs: [out],
    extra_signatories: [agent_key],
    validity_range: interval.between(hi - 60_000, hi),
  }
}

fn ada_rec(at: Int, amount: Int) -> SpendRecord {
  SpendRecord { policy: #"", name: #"", at, amount }
}

fn agent_ok(d: GuardDatum, tx: Transaction) -> Bool {
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

/// 50 ADA already spent in the window: one more ADA must be refused.
fn full_window() -> GuardDatum {
  GuardDatum { ..base_datum(), spends: [ada_rec(hi - 1_000, 50_000_000)] }
}

test full_window_refuses_one_more_ada() fail {
  let start = full_window()
  let after = GuardDatum {
    ..start,
    spends: [ada_rec(hi, 1_000_000), ..start.spends],
  }
  agent_ok(
    start,
    agent_tx(
      guard_in(v_base(100_000_000), start),
      cont(v_base(99_000_000), after),
    ),
  )
}

/// A negative record planted in the opening datum used to offset the window.
test negative_spend_record_cannot_offset_the_window() fail {
  let poison = ada_rec(2_000_000_000_000, -1_000_000_000)
  let start = GuardDatum {
    ..full_window(),
    spends: [poison, ..full_window().spends],
  }
  let after = GuardDatum {
    ..start,
    spends: [ada_rec(hi, 20_000_000), ..start.spends],
  }
  agent_ok(
    start,
    agent_tx(
      guard_in(v_base(100_000_000), start),
      cont(v_base(80_000_000), after),
    ),
  )
}

/// A zero record is refused too: only real outflow is ever recorded.
test zero_spend_record_is_refused() fail {
  let start = GuardDatum { ..base_datum(), spends: [ada_rec(hi - 1_000, 0)] }
  let after = GuardDatum {
    ..start,
    spends: [ada_rec(hi, 1_000_000), ..start.spends],
  }
  agent_ok(
    start,
    agent_tx(
      guard_in(v_base(100_000_000), start),
      cont(v_base(99_000_000), after),
    ),
  )
}

/// A window shorter than the clock skew used to prune every record at once.
test non_positive_window_cannot_void_the_daily_cap() fail {
  let start = GuardDatum { ..full_window(), window_len: -180_001 }
  let after = GuardDatum { ..start, spends: [ada_rec(hi, 20_000_000)] }
  agent_ok(
    start,
    agent_tx(
      guard_in(v_base(100_000_000), start),
      cont(v_base(80_000_000), after),
    ),
  )
}

test zero_window_is_refused() fail {
  let start = GuardDatum { ..base_datum(), window_len: 0 }
  let after = GuardDatum { ..start, spends: [ada_rec(hi, 1_000_000)] }
  agent_ok(
    start,
    agent_tx(
      guard_in(v_base(100_000_000), start),
      cont(v_base(99_000_000), after),
    ),
  )
}

/// A second token of the state-token policy on the continuation used to kill the
/// agent branch for good.
test continuation_cannot_carry_a_second_state_token() fail {
  let start = base_datum()
  let after = GuardDatum { ..start, spends: [ada_rec(hi, 1_000_000)] }
  let out_v = v_base(99_000_000) |> assets.add(stt_policy, other_stt_name, 1)
  let tx = Transaction {
    ..agent_tx(guard_in(v_base(100_000_000), start), cont(out_v, after)),
    mint: assets.from_asset(stt_policy, other_stt_name, 1),
  }
  agent_ok(start, tx)
}

test continuation_cannot_carry_a_reference_script() fail {
  let start = base_datum()
  let after = GuardDatum { ..start, spends: [ada_rec(hi, 1_000_000)] }
  let out = Output {
    ..cont(v_base(99_000_000), after),
    reference_script: Some(
      #"00000000000000000000000000000000000000000000000000000eee",
    ),
  }
  agent_ok(start, agent_tx(guard_in(v_base(100_000_000), start), out))
}

test honest_spend_with_valid_history_passes() {
  let start = GuardDatum {
    ..base_datum(),
    spends: [ada_rec(hi - 1_000, 30_000_000)],
  }
  let after = GuardDatum {
    ..start,
    spends: [ada_rec(hi, 20_000_000), ..start.spends],
  }
  agent_ok(
    start,
    agent_tx(
      guard_in(v_base(100_000_000), start),
      cont(v_base(80_000_000), after),
    ),
  )
}

/// The owner keeps full control of a guard whatever its datum holds.
test owner_can_sweep_a_poisoned_guard() {
  let start = GuardDatum {
    ..base_datum(),
    window_len: -1,
    spends: [ada_rec(2_000_000_000_000, -1)],
  }
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [guard_in(v_base(100_000_000), start)],
    extra_signatories: [owner_key],
  }
  logic.spend_ok(start, OwnerSpend, own_ref(), tx)
}
