//// Universal one-shot state-thread token (STT) for the ADAM guard v2.
////
//// UNPARAMETERIZED — so its policy id is fixed and a client can PIN it (hash the
//// compiled code, no apply_params). Uniqueness comes from the token NAME rather
//// than a script parameter: name = blake2b_256(cbor.serialise(genesis ref)) of a
//// UTxO consumed in the mint tx. That UTxO can only be spent once, so each name
//// can only be minted once. Exactly one token, one name, per mint; burn is -1.
////
//// A mint opens a guard: the token must land at the guard script on an opening
//// datum the guard can run under and the owner can always exit. The burn checks
//// nothing else, so closing a guard never depends on its state.

use aiken/cbor
use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{blake2b_256}
use cardano/address.{Script}
use cardano/assets.{AssetName, PolicyId, lovelace_of, quantity_of}
use cardano/transaction.{InlineDatum, Transaction}
use guard/logic
use guard/types.{GuardDatum}

/// The script hash of the compiled `guard` validator in plutus.json. The guard
/// does not depend on this policy, so there is no hash cycle; any change to the
/// guard must be followed by updating this constant and rebuilding.
pub const guard_script_hash: ByteArray =
  #"8daa9ed8f913173d6e9360a5783bc9f9bdc7399526ff174b340ef3ff"

validator state_token {
  mint(_redeemer: Data, policy_id: PolicyId, tx: Transaction) {
    expect [Pair(name, amount)] = tx.mint
      |> assets.tokens(policy_id)
      |> dict.to_pairs()
    when amount is {
      // Mint the singleton: some input's OutputReference must hash to the token
      // name — that ties the name to a specific, single-use UTxO (one-shot).
      1 -> and {
          list.any(
            tx.inputs,
            fn(i) { blake2b_256(cbor.serialise(i.output_reference)) == name },
          ),
          opens_guard(policy_id, name, tx),
        }
      // Burn on guard close/revoke.
      -1 -> True
      _ -> False
    }
  }

  else(_) {
    fail
  }
}

fn opens_guard(policy_id: PolicyId, name: AssetName, tx: Transaction) -> Bool {
  expect [guard_out] = list.filter(
    tx.outputs,
    fn(o) { quantity_of(o.value, policy_id, name) > 0 },
  )
  expect InlineDatum(raw) = guard_out.datum
  expect datum: GuardDatum = raw
  and {
    guard_out.address.payment_credential == Script(guard_script_hash),
    guard_out.reference_script == None,
    dict.to_pairs(assets.tokens(guard_out.value, policy_id)) == [Pair(name, 1)],
    list.length(assets.flatten(assets.without_lovelace(guard_out.value))) <= logic.max_assets,
    lovelace_of(guard_out.value) >= datum.min_principal,
    datum.stt_policy == policy_id,
    datum.spends == [],
    !datum.kill,
    logic.terms_ok(datum),
    list.has(tx.extra_signatories, datum.owner),
  }
}
