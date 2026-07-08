//// One-shot state-thread token (STT) minting policy for the ADAM guard.
////
//// The STT authenticates the single canonical guard UTxO — it makes the daily
//// accumulator non-forgeable (no older copy to roll back to, no parallel fork
//// to drain the cap N times). Hardened per the red-team: minting requires
//// consuming a specific genesis UTxO AND mints EXACTLY one token; only a single
//// token may ever be burned. No other quantity is permitted.

use aiken/collection/dict
use aiken/collection/list
use cardano/address
use cardano/assets.{PolicyId}
use cardano/transaction.{Input, NoDatum, Output, OutputReference, Transaction}

validator state_token(genesis: OutputReference) {
  mint(_redeemer: Data, policy_id: PolicyId, tx: Transaction) {
    // The value this tx mints/burns under THIS policy: expect exactly one name.
    expect [Pair(_name, amount)] =
      tx.mint |> assets.tokens(policy_id) |> dict.to_pairs()

    when amount is {
      // Mint the singleton: one-shot — the unique genesis UTxO must be consumed
      // in this same tx, so it can never be minted twice.
      1 -> list.any(tx.inputs, fn(i) { i.output_reference == genesis })
      // Burn the singleton (guard close/revoke). Genesis is long gone; allow -1.
      -1 -> True
      // Any other quantity is forbidden.
      _ -> False
    }
  }

  else(_) {
    fail
  }
}

// ── Tests ──────────────────────────────────────────────────────────────────

const pol: ByteArray = #"00000000000000000000000000000000000000000000000000000abc"

const nm: ByteArray = "GUARD"

const gtx: ByteArray =
  #"2222222222222222222222222222222222222222222222222222222222222222"

fn genesis_ref() -> OutputReference {
  OutputReference { transaction_id: gtx, output_index: 0 }
}

fn genesis_input() -> Input {
  Input {
    output_reference: genesis_ref(),
    output: Output {
      address: address.from_verification_key(#"00"),
      value: assets.from_lovelace(2_000_000),
      datum: NoDatum,
      reference_script: None,
    },
  }
}

test mint_one_with_genesis_passes() {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [genesis_input()],
      mint: assets.from_asset(pol, nm, 1),
    }
  state_token.mint(genesis_ref(), Void, pol, tx)
}

test mint_without_genesis_fails() fail {
  let tx =
    Transaction { ..transaction.placeholder, mint: assets.from_asset(pol, nm, 1) }
  state_token.mint(genesis_ref(), Void, pol, tx)
}

test mint_two_fails() fail {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [genesis_input()],
      mint: assets.from_asset(pol, nm, 2),
    }
  state_token.mint(genesis_ref(), Void, pol, tx)
}

test burn_one_passes() {
  let tx =
    Transaction { ..transaction.placeholder, mint: assets.from_asset(pol, nm, -1) }
  state_token.mint(genesis_ref(), Void, pol, tx)
}
