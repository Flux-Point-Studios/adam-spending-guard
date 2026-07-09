# STT-name conformance vectors

The ADAM guard v2 uses a **universal, unparameterized** state-thread token
(`validators/state_token.ak`). Its *policy id* is fixed (so a client can pin it by
hashing the compiled code — no `apply_params`), and per-guard uniqueness comes from
the token **name**:

```
name = blake2b_256( cbor.serialise(genesis_out_ref) )
```

where `genesis_out_ref` is the `OutputReference` of a UTxO consumed in the mint tx.
That UTxO can be spent only once, so each name can be minted only once (one-shot).

An off-chain host (the Gero iOS wallet) attests a guard **hash-only**: it pins the
guard script hash + STT policy id, reads the datum, and checks `datum.owner == myKey`.
To also verify the STT is *this guard's* singleton it must recompute the name — which
means reproducing `cbor.serialise(OutputReference)` **byte-for-byte**. This file is
that interop contract.

## Encoding

`OutputReference { transaction_id: Hash<Blake2b_256, Transaction>, output_index: Int }`
serialises as Plutus `Data` — constructor 0 with an **indefinite-length** field array:

```
D8 79              tag 121            (constructor index 0)
9F                 array(*)           INDEFINITE-length   <-- NOT 0x82 definite
  58 20 <32 bytes> bytestring(32)     transaction_id
  <uint>           unsigned int       output_index (canonical CBOR uint)
FF                 break
```

### ⚠️ The two traps

1. **Indefinite array.** Aiken's `cbor.serialise` emits `9F … FF`, *not* a definite
   `82 …` array. Hashing the definite form yields the wrong name.
2. **It is Plutus `Data`, not a CSL `TransactionInput`.**
   `cardano-serialization-lib` serialises a `TransactionInput` as a bare 2-array
   `[bytes, index]` with **no** constructor tag. You must instead build a
   `PlutusData::ConstrPlutusData(alt=0, [Bytes(txid), Int(index)])` and ensure it
   encodes the field list as an **indefinite** array. Verify against the vectors
   below before trusting any name check.

The `output_index` is a canonical CBOR unsigned integer, so its width changes with
magnitude (`0x00`, `0x18 18` for 24, `0x19 01 00` for 256, …). The vectors cover
these transitions.

## Vectors

Each row is asserted (bytes **and** name) by `validators/stt_name_conformance_test.ak`,
which runs under `aiken check` — so these values are ground truth from the toolchain,
not hand-derived.

| tx id (32 bytes) | index | `cbor.serialise(out_ref)` | `blake2b_256` name |
|---|---|---|---|
| `1111111111111111111111111111111111111111111111111111111111111111` | 0 | `d8799f5820111111111111111111111111111111111111111111111111111111111111111100ff` | `56664296ffc0310952b2bc81548beb7512c002c4ffac4dea24041ad10ac40fdd` |
| `1111111111111111111111111111111111111111111111111111111111111111` | 1 | `d8799f5820111111111111111111111111111111111111111111111111111111111111111101ff` | `e6b82f9f17464ed2994ea77bb177f40868f65b48bf290ff060e001cd3000a616` |
| `de1dc0ffee0badf00dcafe0000feed00badc0ffee0dea1beefdeadbeef123456` | 7 | `d8799f5820de1dc0ffee0badf00dcafe0000feed00badc0ffee0dea1beefdeadbeef12345607ff` | `cdbee5715b253d5c1cae1454545c401c7aa349fb389f0c4ec281d3182b1eb1bd` |
| `0000000000000000000000000000000000000000000000000000000000000000` | 24 | `d8799f582000000000000000000000000000000000000000000000000000000000000000001818ff` | `d85cc298557426f945643e89a5efa048b7bed47870001b782a3a9e839cd1980c` |
| `ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` | 256 | `d8799f5820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff190100ff` | `342691bdfe783a0be69087fedb4a2a0c4aa906f37273eb91866f5e01b3fa509d` |

## Reproduce / regenerate

```
aiken check -m stt_name        # runs the conformance tests
```

To (re)derive independently — e.g. to cross-check a host implementation — the
reference bytes above were produced by `blake2b_256` over the CBOR shown; any Plutus
`Data` encoder that matches the "Encoding" section will reproduce them.

When the guard is productionized, add one row per real genesis outref if desired; the
encoding itself is stable across stdlib v3.x.
