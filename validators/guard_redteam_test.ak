//// Red-team hardening suite for ADAM guard v2 (per-asset caps) — adversarial txs
//// that MUST be rejected. Each is a `fail` test: it passes iff `logic.spend_ok`
//// rejects the attack (returns False or trips an `expect`). Complements the
//// baseline + ported suites; focuses on the shared universal-address singleton,
//// STT authentication, and the validity-window / datum-invariance edges.
////
//// Ported from fable's v2-pinnable red-team, adapted to the per-asset datum
//// (token_caps + 4-field SpendRecord). The token-exfiltration findings F-1/F-2
//// are CLOSED and proved rejected in security_findings_test.ak.

use aiken/interval
use cardano/address
use cardano/assets.{Value}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}
use guard/logic
use guard/types.{AgentSpend, AssetCap, GuardDatum, SpendRecord}

const owner_key: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000a"

const agent_key: ByteArray =
  #"0000000000000000000000000000000000000000000000000000000b"

const stt_policy: ByteArray =
  #"00000000000000000000000000000000000000000000000000000abc"

const stt_name: ByteArray =
  #"9999999999999999999999999999999999999999999999999999999999999999"

const stt_name_b: ByteArray =
  #"8888888888888888888888888888888888888888888888888888888888888888"

const foreign_policy: ByteArray =
  #"00000000000000000000000000000000000000000000000000000eee"

const guard_script: ByteArray =
  #"00000000000000000000000000000000000000000000000000000fff"

const own_tx_id: ByteArray =
  #"1111111111111111111111111111111111111111111111111111111111111111"

const other_tx_id: ByteArray =
  #"2222222222222222222222222222222222222222222222222222222222222222"

fn base_datum() -> GuardDatum {
  GuardDatum {
    owner: owner_key,
    stt_policy,
    agent: agent_key,
    per_tx_cap: 20_000_000,
    daily_cap: 50_000_000,
    window_len: 86_400_000,
    token_caps: [],
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

fn own_ref() -> OutputReference {
  OutputReference { transaction_id: own_tx_id, output_index: 0 }
}

fn stt_ada(ada: Int) -> Value {
  assets.from_lovelace(ada) |> assets.add(stt_policy, stt_name, 1)
}

fn ginput(v: Value, d: GuardDatum, r: OutputReference) -> Input {
  Input {
    output_reference: r,
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

fn hi() -> Int {
  1_000_000_060_000
}

fn ok_range() {
  interval.between(hi() - 60_000, hi())
}

fn ada_rec(amount: Int) -> SpendRecord {
  SpendRecord { policy: #"", name: #"", at: hi(), amount }
}

fn cont_d10() -> GuardDatum {
  GuardDatum { ..base_datum(), spends: [ada_rec(10_000_000)] }
}

// ── Shared universal-address singleton ───────────────────────────────────────

/// Two guard UTxOs (A being validated + guard B with its own STT) as inputs:
/// double-satisfaction across the SHARED script address. `expect [guard_in]` trips.
test rt_two_guard_inputs_rejected() fail {
  let d = base_datum()
  let vb = assets.from_lovelace(100_000_000)
    |> assets.add(stt_policy, stt_name_b, 1)
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [
      ginput(stt_ada(100_000_000), d, own_ref()),
      ginput(
        vb,
        d,
        OutputReference { transaction_id: other_tx_id, output_index: 0 },
      ),
    ],
    outputs: [cont_o(stt_ada(90_000_000), cont_d10())],
    extra_signatories: [agent_key],
    validity_range: ok_range(),
  }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

/// A foreign (non-guard) UTxO co-located at the universal guard address as a
/// second input. Also documents the LIVENESS edge: the tx-builder must never let
/// a second input land at the guard address (`expect [guard_in]` is fail-closed).
test rt_foreign_utxo_at_guard_addr_rejected() fail {
  let d = base_datum()
  let junk = Input {
    output_reference: OutputReference {
      transaction_id: other_tx_id,
      output_index: 9,
    },
    output: Output {
      address: guard_addr(),
      value: assets.from_lovelace(2_000_000),
      datum: NoDatum,
      reference_script: None,
    },
  }
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [ginput(stt_ada(100_000_000), d, own_ref()), junk],
    outputs: [cont_o(stt_ada(90_000_000), cont_d10())],
    extra_signatories: [agent_key],
    validity_range: ok_range(),
  }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

/// Two STT-bearing outputs (ambiguous continuation). `expect [cont]` trips.
test rt_duplicate_stt_continuation_rejected() fail {
  let d = base_datum()
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [ginput(stt_ada(100_000_000), d, own_ref())],
    outputs: [
      cont_o(stt_ada(45_000_000), cont_d10()),
      cont_o(stt_ada(45_000_000), cont_d10()),
    ],
    extra_signatories: [agent_key],
    validity_range: ok_range(),
  }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

// ── STT authentication ───────────────────────────────────────────────────────

/// Spent UTxO carries only a FOREIGN-policy token, none under datum.stt_policy.
test rt_foreign_policy_not_stt_rejected() fail {
  let d = base_datum()
  let v = assets.from_lovelace(100_000_000)
    |> assets.add(foreign_policy, stt_name, 1)
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [ginput(v, d, own_ref())],
    outputs: [cont_o(v, cont_d10())],
    extra_signatories: [agent_key],
    validity_range: ok_range(),
  }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

/// Two different STT names under the SAME policy on the spent UTxO. `expect [Pair]` trips.
test rt_two_stt_names_rejected() fail {
  let d = base_datum()
  let v = stt_ada(100_000_000) |> assets.add(stt_policy, stt_name_b, 1)
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [ginput(v, d, own_ref())],
    outputs: [cont_o(v, cont_d10())],
    extra_signatories: [agent_key],
    validity_range: ok_range(),
  }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

/// Burning the current STT in the same tx. `no_stt_mint` requires mint(stt_nm)==0.
test rt_burn_current_stt_rejected() fail {
  let d = base_datum()
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [ginput(stt_ada(100_000_000), d, own_ref())],
    outputs: [cont_o(stt_ada(90_000_000), cont_d10())],
    mint: assets.from_asset(stt_policy, stt_name, -1),
    extra_signatories: [agent_key],
    validity_range: ok_range(),
  }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

// ── Validity window & datum invariance ───────────────────────────────────────

/// now == expiry boundary: `not_expired = now < expiry` must be strict.
test rt_now_equals_expiry_rejected() fail {
  let d = GuardDatum { ..base_datum(), expiry: hi() }
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [ginput(stt_ada(100_000_000), d, own_ref())],
    outputs: [
      cont_o(
        stt_ada(90_000_000),
        GuardDatum { ..d, spends: [ada_rec(10_000_000)] },
      ),
    ],
    extra_signatories: [agent_key],
    validity_range: ok_range(),
  }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

/// Validity window wider than max_skew (200s > 180s). `range_ok` fails.
test rt_excessive_skew_rejected() fail {
  let d = base_datum()
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [ginput(stt_ada(100_000_000), d, own_ref())],
    outputs: [cont_o(stt_ada(90_000_000), cont_d10())],
    extra_signatories: [agent_key],
    validity_range: interval.between(hi() - 200_000, hi()),
  }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

/// Continuation forwards an altered owner-controlled field (expiry). `datum_ok` fails.
test rt_altered_expiry_datum_rejected() fail {
  let d = base_datum()
  let bad = GuardDatum {
    ..d,
    expiry: 9_999_999_999_999,
    spends: [ada_rec(10_000_000)],
  }
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [ginput(stt_ada(100_000_000), d, own_ref())],
    outputs: [cont_o(stt_ada(90_000_000), bad)],
    extra_signatories: [agent_key],
    validity_range: ok_range(),
  }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

/// Continuation forwards an altered token_caps (agent tries to DECLARE a token to
/// unlock it / widen caps). `datum_ok` fails — caps are owner-only.
test rt_altered_token_caps_datum_rejected() fail {
  let d = base_datum()
  let bad = GuardDatum {
    ..d,
    token_caps: [
      AssetCap {
        policy: foreign_policy,
        name: stt_name,
        per_tx: 1_000_000,
        daily: 9_000_000,
      },
    ],
    spends: [ada_rec(10_000_000)],
  }
  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [ginput(stt_ada(100_000_000), d, own_ref())],
    outputs: [cont_o(stt_ada(90_000_000), bad)],
    extra_signatories: [agent_key],
    validity_range: ok_range(),
  }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}
