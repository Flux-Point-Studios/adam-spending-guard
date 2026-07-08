//// Universal one-shot state-thread token (STT) for the ADAM guard v2.
////
//// UNPARAMETERIZED — so its policy id is fixed and a client can PIN it (hash the
//// compiled code, no apply_params). Uniqueness comes from the token NAME rather
//// than a script parameter: name = blake2b_256(cbor.serialise(genesis ref)) of a
//// UTxO consumed in the mint tx. That UTxO can only be spent once, so each name
//// can only be minted once. Exactly one token, one name, per mint; burn is -1.

use aiken/cbor
use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{blake2b_256}
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}

validator state_token {
  mint(_redeemer: Data, policy_id: PolicyId, tx: Transaction) {
    expect [Pair(name, amount)] =
      tx.mint |> assets.tokens(policy_id) |> dict.to_pairs()
    when amount is {
      // Mint the singleton: some input's OutputReference must hash to the token
      // name — that ties the name to a specific, single-use UTxO (one-shot).
      1 ->
        list.any(
          tx.inputs,
          fn(i) { blake2b_256(cbor.serialise(i.output_reference)) == name },
        )
      // Burn on guard close/revoke.
      -1 -> True
      _ -> False
    }
  }

  else(_) {
    fail
  }
}
