//// SECURITY FINDINGS — CLOSURE PROOFS. See SECURITY-FINDINGS.md.
////
//// fable's independent red-team of the v2-pinnable (lovelace-only) guard found
//// F-1 and F-2: the agent branch metered LOVELACE only, so a compromised session
//// key could ship the guard's native tokens to an attacker for free (outflow=0,
//// or even negative outflow so no spend record was written).
////
//// These are fable's EXACT reproducers, now inverted per his instruction
//// ("after the token-metering fix lands, INVERT each … so it becomes a passing
//// regression test proving the drain is now rejected"). Under the per-asset-caps
//// validator the drained token T is UNDECLARED (not in `token_caps`), so
//// `conserve_undeclared` requires the continuation to retain >= its input
//// quantity — the exfiltration output makes `quantity_of(cont, T) = 0 < input`,
//// and the validator REJECTS. Each `fail` test therefore proves F-1/F-2 CLOSED.

use aiken/interval
use cardano/address
use cardano/assets.{Value}
use cardano/transaction.{InlineDatum, Input, NoDatum, Output, OutputReference, Transaction}
use guard/logic
use guard/types.{AgentSpend, AssetCap, GuardDatum}

const owner_key: ByteArray = #"0000000000000000000000000000000000000000000000000000000a"
const agent_key: ByteArray = #"0000000000000000000000000000000000000000000000000000000b"
const attacker_key: ByteArray = #"0000000000000000000000000000000000000000000000000000000c"
const stt_policy: ByteArray = #"00000000000000000000000000000000000000000000000000000abc"
const stt_name: ByteArray = #"9999999999999999999999999999999999999999999999999999999999999999"
const guard_script: ByteArray = #"00000000000000000000000000000000000000000000000000000fff"
const own_tx_id: ByteArray = #"1111111111111111111111111111111111111111111111111111111111111111"
const token_policy: ByteArray = #"00000000000000000000000000000000000000000000000000000ddd"
const token_name: ByteArray = #"7454"

// Base datum with NO declared token caps: T is therefore an UNDECLARED asset that
// the agent may acquire but never move out (conserve_undeclared).
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

// A datum that DECLARES T with a quantity cap, used to show the metered path also
// bounds a declared token's net outflow.
fn declared_datum() -> GuardDatum {
  GuardDatum {
    ..base_datum(),
    token_caps: [AssetCap { policy: token_policy, name: token_name, per_tx: 100, daily: 200 }],
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

fn stt_ada_tok(ada: Int, tq: Int) -> Value {
  stt_ada(ada) |> assets.add(token_policy, token_name, tq)
}

fn ginput(v: Value, d: GuardDatum) -> Input {
  Input {
    output_reference: own_ref(),
    output: Output { address: guard_addr(), value: v, datum: InlineDatum(d), reference_script: None },
  }
}

fn cont_o(v: Value, d: GuardDatum) -> Output {
  Output { address: guard_addr(), value: v, datum: InlineDatum(d), reference_script: None }
}

fn steal(v: Value) -> Output {
  Output { address: address.from_verification_key(attacker_key), value: v, datum: NoDatum, reference_script: None }
}

fn okr() {
  interval.between(1_000_000_000_000, 1_000_000_060_000)
}

/// F-1 CLOSED: agent tries to drain 1000·T (undeclared) to an attacker while ADA is
/// unchanged (outflow = 0). Under per-asset caps `conserve_undeclared` requires the
/// continuation to keep >= 1000·T; it keeps 0 → REJECTED. (Was accepted on v2-pinnable.)
test f1_token_exfiltration_now_rejected() fail {
  let d = base_datum()
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [ginput(stt_ada_tok(100_000_000, 1000), d)],
      outputs: [
        cont_o(stt_ada(100_000_000), d),
        steal(assets.from_lovelace(2_000_000) |> assets.add(token_policy, token_name, 1000)),
      ],
      extra_signatories: [agent_key],
      validity_range: okr(),
    }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

/// F-2 CLOSED: drain hidden by negative outflow (ADA up so no ADA spend record).
/// The token is still undeclared, so conserve_undeclared REJECTS regardless of the
/// ADA accounting. (Was accepted on v2-pinnable — no record, caps blind.)
test f2_negative_outflow_token_drain_now_rejected() fail {
  let d = base_datum()
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [ginput(stt_ada_tok(50_000_000, 500), d)],
      outputs: [
        cont_o(stt_ada(60_000_000), d),
        steal(assets.from_lovelace(2_000_000) |> assets.add(token_policy, token_name, 500)),
      ],
      extra_signatories: [agent_key],
      validity_range: okr(),
    }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

/// Even when T IS declared (metered like ADA), a net outflow above the per-tx cap is
/// rejected — the compromised agent is bounded by the OWNER-set quantity, not free.
/// Declares per_tx=100; tries to move 500 out (input 500 → cont 0). REJECTED.
test f1_declared_token_over_cap_now_rejected() fail {
  let d = declared_datum()
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [ginput(stt_ada_tok(50_000_000, 500), d)],
      outputs: [
        cont_o(stt_ada(52_000_000), d),
        steal(assets.from_lovelace(2_000_000) |> assets.add(token_policy, token_name, 500)),
      ],
      extra_signatories: [agent_key],
      validity_range: okr(),
    }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}
