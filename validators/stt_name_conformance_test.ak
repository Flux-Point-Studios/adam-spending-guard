//// STT-name conformance vectors for the ADAM guard v2 (Plutus V3).
////
//// The universal STT (state_token.ak) is a one-shot whose NAME binds it to a
//// single genesis UTxO:  name = blake2b_256(cbor.serialise(genesis_out_ref)).
//// An off-chain client (the Gero iOS wallet) must reproduce that name BYTE-FOR-
//// BYTE to attest a guard hash-only. The exact CBOR that `cbor.serialise` emits
//// for an `OutputReference` is the interop contract, so these tests PIN it:
//// each asserts the exact serialised bytes AND the resulting blake2b_256 name.
////
//// Encoding (verified by these tests):
////   OutputReference = Constr 0 [ transaction_id: bytes(32), output_index: Int ]
////   cbor.serialise  = D8 79            tag 121 (constructor 0)
////                     9F              array(*) INDEFINITE-length  <-- NOT 0x82
////                       58 20 <32b>   the tx id (bytestring, 32)
////                       <uint>        the output index (canonical CBOR uint)
////                     FF              break
////
//// NOTE for host implementers: the field array is INDEFINITE-length (9F..FF).
//// A naive definite-array encoding (0x82 ...) or a CSL/cardano-serialization-lib
//// `TransactionInput` (which serialises as a plain 2-array, no constr tag) will
//// hash to the WRONG name. Build a Plutus Data Constr(0,[bytes,int]) and match
//// these vectors before trusting the name check. See CONFORMANCE.md.

use aiken/cbor
use aiken/crypto.{blake2b_256}
use cardano/transaction.{OutputReference}

// all-1s tx, index 0: index 0 exercises CBOR uint width
test stt_name_all1s_tx_index_0() {
  let genesis = OutputReference {
    transaction_id: #"1111111111111111111111111111111111111111111111111111111111111111",
    output_index: 0,
  }
  let serialised = cbor.serialise(genesis)
  and {
    serialised == #"d8799f5820111111111111111111111111111111111111111111111111111111111111111100ff",
    blake2b_256(serialised) == #"56664296ffc0310952b2bc81548beb7512c002c4ffac4dea24041ad10ac40fdd",
  }
}

// all-1s tx, index 1: index 1 exercises CBOR uint width
test stt_name_all1s_tx_index_1() {
  let genesis = OutputReference {
    transaction_id: #"1111111111111111111111111111111111111111111111111111111111111111",
    output_index: 1,
  }
  let serialised = cbor.serialise(genesis)
  and {
    serialised == #"d8799f5820111111111111111111111111111111111111111111111111111111111111111101ff",
    blake2b_256(serialised) == #"e6b82f9f17464ed2994ea77bb177f40868f65b48bf290ff060e001cd3000a616",
  }
}

// realistic tx, index 7: index 7 exercises CBOR uint width
test stt_name_realistic_tx_index_7() {
  let genesis = OutputReference {
    transaction_id: #"de1dc0ffee0badf00dcafe0000feed00badc0ffee0dea1beefdeadbeef123456",
    output_index: 7,
  }
  let serialised = cbor.serialise(genesis)
  and {
    serialised == #"d8799f5820de1dc0ffee0badf00dcafe0000feed00badc0ffee0dea1beefdeadbeef12345607ff",
    blake2b_256(serialised) == #"cdbee5715b253d5c1cae1454545c401c7aa349fb389f0c4ec281d3182b1eb1bd",
  }
}

// zeros tx, index 24: index 24 exercises CBOR uint width
test stt_name_zeros_tx_index_24() {
  let genesis = OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
    output_index: 24,
  }
  let serialised = cbor.serialise(genesis)
  and {
    serialised == #"d8799f582000000000000000000000000000000000000000000000000000000000000000001818ff",
    blake2b_256(serialised) == #"d85cc298557426f945643e89a5efa048b7bed47870001b782a3a9e839cd1980c",
  }
}

// all-f tx, index 256: index 256 exercises CBOR uint width
test stt_name_allf_tx_index_256() {
  let genesis = OutputReference {
    transaction_id: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    output_index: 256,
  }
  let serialised = cbor.serialise(genesis)
  and {
    serialised == #"d8799f5820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff190100ff",
    blake2b_256(serialised) == #"342691bdfe783a0be69087fedb4a2a0c4aa906f37273eb91866f5e01b3fa509d",
  }
}
