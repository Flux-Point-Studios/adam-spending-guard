//// SECURITY FINDINGS — reproducers, confirmed by execution. See SECURITY-FINDINGS.md.
////
//// These tests DOCUMENT CURRENT (vulnerable) behavior: they assert the guard
//// ACCEPTS a native-token drain today (`spend_ok(...) == True`). They are green so
//// the suite stays green — but each marks an OPEN vulnerability (F-1, F-2).
////
//// >> After the token-metering fix lands, INVERT each: replace the body with
//// >>   `test <name>_rejected() fail { logic.spend_ok(...) }`
//// >> so it becomes a passing regression test proving the drain is now rejected.

use aiken/interval
use cardano/address
use cardano/assets.{Value}
use cardano/transaction.{InlineDatum, Input, NoDatum, Output, OutputReference, Transaction}
use guard/logic
use guard/types.{AgentSpend, GuardDatum, SpendRecord}

const owner_key: ByteArray = #"0000000000000000000000000000000000000000000000000000000a"
const agent_key: ByteArray = #"0000000000000000000000000000000000000000000000000000000b"
const attacker_key: ByteArray = #"0000000000000000000000000000000000000000000000000000000c"
const stt_policy: ByteArray = #"00000000000000000000000000000000000000000000000000000abc"
const stt_name: ByteArray = #"9999999999999999999999999999999999999999999999999999999999999999"
const guard_script: ByteArray = #"00000000000000000000000000000000000000000000000000000fff"
const own_tx_id: ByteArray = #"1111111111111111111111111111111111111111111111111111111111111111"
const token_policy: ByteArray = #"00000000000000000000000000000000000000000000000000000ddd"
const token_name: ByteArray = #"7454"

fn base_datum() -> GuardDatum {
  GuardDatum { owner: owner_key, stt_policy, agent: agent_key, per_tx_cap: 20_000_000,
    daily_cap: 50_000_000, window_len: 86_400_000, spends: [], min_principal: 5_000_000,
    max_spends: 10, expiry: 2_000_000_000_000, kill: False }
}
fn guard_addr() -> address.Address { address.from_script(guard_script) }
fn own_ref() -> OutputReference { OutputReference { transaction_id: own_tx_id, output_index: 0 } }
fn stt_ada(ada: Int) -> Value { assets.from_lovelace(ada) |> assets.add(stt_policy, stt_name, 1) }
fn stt_ada_tok(ada: Int, tq: Int) -> Value { stt_ada(ada) |> assets.add(token_policy, token_name, tq) }
fn ginput(v: Value, d: GuardDatum) -> Input {
  Input { output_reference: own_ref(), output: Output { address: guard_addr(), value: v, datum: InlineDatum(d), reference_script: None } }
}
fn cont_o(v: Value, d: GuardDatum) -> Output { Output { address: guard_addr(), value: v, datum: InlineDatum(d), reference_script: None } }
fn steal(v: Value) -> Output { Output { address: address.from_verification_key(attacker_key), value: v, datum: NoDatum, reference_script: None } }
fn okr() { interval.between(1_000_000_000_000, 1_000_000_060_000) }

/// F-1 (FIXED): agent tries to drain 1000·T to an attacker while ADA is unchanged
/// (outflow = 0). Token conservation now REJECTS it.
test token_exfiltration_rejected() fail {
  let d = base_datum()
  let tx = Transaction { ..transaction.placeholder,
    inputs: [ginput(stt_ada_tok(100_000_000, 1000), d)],
    outputs: [cont_o(stt_ada(100_000_000), d), steal(assets.from_lovelace(2_000_000) |> assets.add(token_policy, token_name, 1000))],
    extra_signatories: [agent_key], validity_range: okr() }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

/// F-2 (FIXED): drain hidden by negative outflow (ada_out > ada_in). Token
/// conservation now REJECTS it regardless of the ADA direction.
test negative_outflow_token_drain_rejected() fail {
  let d = base_datum()
  let tx = Transaction { ..transaction.placeholder,
    inputs: [ginput(stt_ada_tok(50_000_000, 500), d)],
    outputs: [cont_o(stt_ada(60_000_000), d), steal(assets.from_lovelace(2_000_000) |> assets.add(token_policy, token_name, 500))],
    extra_signatories: [agent_key], validity_range: okr() }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}

/// A legitimate BUY still passes: ADA leaves within cap, the token position GROWS
/// (500 -> 600), STT + datum conserved — so the fix closes exfiltration without
/// blocking token acquisition.
test buy_grows_token_position_accepted() {
  let d = base_datum()
  let cont_d =
    GuardDatum { ..d, spends: [SpendRecord { at: 1_000_000_060_000, amount: 10_000_000 }] }
  let tx = Transaction { ..transaction.placeholder,
    inputs: [ginput(stt_ada_tok(100_000_000, 500), d)],
    outputs: [cont_o(stt_ada_tok(90_000_000, 600), cont_d)],
    extra_signatories: [agent_key], validity_range: okr() }
  logic.spend_ok(d, AgentSpend, own_ref(), tx)
}
