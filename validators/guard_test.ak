//// Baseline for per-asset caps. Honest ADA buys + declared-token sells within
//// caps PASS; over-cap sells, undeclared-token exfiltration, and config tamper
//// REJECT. The red-team adds exhaustive adversarial coverage.

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

const tok_pol: ByteArray =
  #"00000000000000000000000000000000000000000000000000001111"

const tok_name: ByteArray = "TKN"

const und_pol: ByteArray =
  #"00000000000000000000000000000000000000000000000000002222"

const und_name: ByteArray = "UND"

const guard_script: ByteArray =
  #"00000000000000000000000000000000000000000000000000000fff"

const own_tx_id: ByteArray =
  #"1111111111111111111111111111111111111111111111111111111111111111"

const hi: Int = 1_000_000_060_000

fn caps() -> List<AssetCap> {
  [AssetCap { policy: tok_pol, name: tok_name, per_tx: 500, daily: 1000 }]
}

fn base_datum() -> GuardDatum {
  GuardDatum {
    owner: owner_key,
    stt_policy,
    agent: agent_key,
    per_tx_cap: 20_000_000,
    daily_cap: 50_000_000,
    window_len: 86_400_000,
    token_caps: caps(),
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

fn v_base(ada: Int) -> Value {
  assets.from_lovelace(ada) |> assets.add(stt_policy, stt_name, 1)
}

fn v_tok(ada: Int, tq: Int) -> Value {
  v_base(ada) |> assets.add(tok_pol, tok_name, tq)
}

fn own_ref() -> OutputReference {
  OutputReference { transaction_id: own_tx_id, output_index: 0 }
}

fn ginput(v: Value, d: GuardDatum) -> Input {
  Input {
    output_reference: own_ref(),
    output: Output {
      address: guard_addr(),
      value: v,
      datum: InlineDatum(d),
      reference_script: None,
    },
  }
}

fn cont_o(v: Value, d: GuardDatum) -> Output {
  Output {
    address: guard_addr(),
    value: v,
    datum: InlineDatum(d),
    reference_script: None,
  }
}

fn tx1(inp: Input, out: Output) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [inp],
    outputs: [out],
    extra_signatories: [agent_key],
    validity_range: interval.between(hi - 60_000, hi),
  }
}

fn ada_rec(amount: Int) -> SpendRecord {
  SpendRecord { policy: #"", name: #"", at: hi, amount }
}

fn tok_rec(amount: Int) -> SpendRecord {
  SpendRecord { policy: tok_pol, name: tok_name, at: hi, amount }
}

fn check(d: GuardDatum, tx: Transaction) -> Bool {
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

// ── Honest paths PASS ───────────────────────────────────────────────────────

/// Buy: 10 ADA leaves, no token moves. ADA record only.
test honest_ada_spend() {
  let d = base_datum()
  let cont_d = GuardDatum { ..d, spends: [ada_rec(10_000_000)] }
  check(
    d,
    tx1(ginput(v_base(100_000_000), d), cont_o(v_base(90_000_000), cont_d)),
  )
}

/// Sell 300·TKN (<= per_tx 500), receiving 10 ADA (ADA increases → no ADA record).
/// One token record for the 300 that left.
test declared_token_sell_within_caps() {
  let d = base_datum()
  let cont_d = GuardDatum { ..d, spends: [tok_rec(300)] }
  check(
    d,
    tx1(
      ginput(v_tok(50_000_000, 1000), d),
      cont_o(v_tok(60_000_000, 700), cont_d),
    ),
  )
}

/// Sell exactly the daily remainder: prior 700 in-window, sell 300 → 1000 == daily.
test declared_token_reaches_daily_cap() {
  let d = base_datum()
  let prior = SpendRecord {
    policy: tok_pol,
    name: tok_name,
    at: hi - 1_000,
    amount: 700,
  }
  let start = GuardDatum { ..d, spends: [prior] }
  let cont_d = GuardDatum { ..start, spends: [tok_rec(300), prior] }
  check(
    start,
    tx1(
      ginput(v_tok(50_000_000, 1000), start),
      cont_o(v_tok(50_000_000, 700), cont_d),
    ),
  )
}

/// Acquiring an UNDECLARED token is fine (it's not on the input; can't leave later).
test buy_undeclared_token_ok() {
  let d = base_datum()
  let cont_d = GuardDatum { ..d, spends: [ada_rec(10_000_000)] }
  let out_v = v_base(90_000_000) |> assets.add(und_pol, und_name, 50)
  check(d, tx1(ginput(v_base(100_000_000), d), cont_o(out_v, cont_d)))
}

test owner_sweep_with_sig() {
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [ginput(v_tok(100_000_000, 500), base_datum())],
    extra_signatories: [owner_key],
  }
  logic.spend_ok(base_datum(), OwnerSpend, own_ref(), tx)
}

// ── Rejections ──────────────────────────────────────────────────────────────

/// Sell 501·TKN > per_tx cap 500.
test declared_token_over_per_tx_rejected() fail {
  let d = base_datum()
  let cont_d = GuardDatum { ..d, spends: [tok_rec(501)] }
  check(
    d,
    tx1(
      ginput(v_tok(50_000_000, 1000), d),
      cont_o(v_tok(60_000_000, 499), cont_d),
    ),
  )
}

/// Prior 800 in-window + sell 300 = 1100 > daily 1000.
test declared_token_over_daily_rejected() fail {
  let d = base_datum()
  let prior = SpendRecord {
    policy: tok_pol,
    name: tok_name,
    at: hi - 1_000,
    amount: 800,
  }
  let start = GuardDatum { ..d, spends: [prior] }
  let cont_d = GuardDatum { ..start, spends: [tok_rec(300), prior] }
  check(
    start,
    tx1(
      ginput(v_tok(50_000_000, 1000), start),
      cont_o(v_tok(50_000_000, 700), cont_d),
    ),
  )
}

/// Exfiltrate an UNDECLARED token that sits on the guard (U 500 -> 0). Rejected.
test undeclared_token_exfiltration_rejected() fail {
  let d = base_datum()
  let cont_d = GuardDatum { ..d, spends: [] }
  let in_v = v_base(100_000_000) |> assets.add(und_pol, und_name, 500)
  check(d, tx1(ginput(in_v, d), cont_o(v_base(100_000_000), cont_d)))
}

/// Agent tries to widen a token cap in the continuing datum.
test agent_cannot_raise_token_cap_rejected() fail {
  let d = base_datum()
  let bad_caps = [
    AssetCap {
      policy: tok_pol,
      name: tok_name,
      per_tx: 1_000_000,
      daily: 9_000_000,
    },
  ]
  let cont_d = GuardDatum { ..d, token_caps: bad_caps, spends: [tok_rec(300)] }
  check(
    d,
    tx1(
      ginput(v_tok(50_000_000, 1000), d),
      cont_o(v_tok(60_000_000, 700), cont_d),
    ),
  )
}

/// ADA leg still enforced: over per_tx ADA cap.
test ada_over_per_tx_rejected() fail {
  let d = base_datum()
  let cont_d = GuardDatum { ..d, spends: [ada_rec(20_000_001)] }
  check(
    d,
    tx1(ginput(v_base(100_000_000), d), cont_o(v_base(79_999_999), cont_d)),
  )
}
