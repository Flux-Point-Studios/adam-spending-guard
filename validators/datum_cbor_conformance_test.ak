//// GuardDatum CBOR conformance vector for the per-asset guard v2 (Plutus V3).
////
//// The client (Gero iOS wallet / AdamKit) must decode the on-chain inline datum
//// byte-for-byte to attest a guard's owner + caps, and the tx-builder must
//// reproduce the continuation datum exactly (the validator's `datum_ok` is a full
//// structural equality). This test PINS `cbor.serialise(GuardDatum)` for a
//// concrete 12-field datum with one declared AssetCap and a mixed spends list
//// (ADA record + token record), so any client encoder can match it.
////
//// Encoding: constructor 0 => tag D8 79, INDEFINITE-length field array 9F..FF, in
//// declared field order: owner, stt_policy, agent, per_tx_cap, daily_cap,
//// window_len, token_caps, spends, min_principal, max_spends, expiry, kill.
//// Each AssetCap and each SpendRecord is itself a Constr-0 (D8 79 9F..FF) record.
//// ADA records/caps use the EMPTY bytestring (CBOR 0x40) for policy AND name.

use aiken/cbor
use guard/types.{AssetCap, GuardDatum, SpendRecord}

const owner_vkh: ByteArray = #"00000000000000000000000000000000000000000000000000000a0a"
const stt_pol: ByteArray = #"5c48f601de2cf0a92d20f351e89704ec85871fafff310cebc7d80704"
const agent_vkh: ByteArray = #"00000000000000000000000000000000000000000000000000000b0b"
const tok_pol: ByteArray = #"00000000000000000000000000000000000000000000000000001111"
const tok_name: ByteArray = "TKN"

fn sample_datum() -> GuardDatum {
  GuardDatum {
    owner: owner_vkh,
    stt_policy: stt_pol,
    agent: agent_vkh,
    per_tx_cap: 20_000_000,
    daily_cap: 50_000_000,
    window_len: 86_400_000,
    token_caps: [AssetCap { policy: tok_pol, name: tok_name, per_tx: 500, daily: 1000 }],
    spends: [
      SpendRecord { policy: #"", name: #"", at: 1_000_000_060_000, amount: 10_000_000 },
      SpendRecord { policy: tok_pol, name: tok_name, at: 1_000_000_060_000, amount: 300 },
    ],
    min_principal: 5_000_000,
    max_spends: 10,
    expiry: 2_000_000_000_000,
    kill: False,
  }
}

// Byte map of the vector below (D8 79 = Constr 0; 9F..FF = indefinite field array;
// 58 1C = bytestring(28); 43 = bytestring(3) "TKN"; empty Constr = D8 79 80):
//   d8799f                                  GuardDatum = Constr 0, [
//     581c <owner 28b>                         owner
//     581c <stt_policy 28b>                    stt_policy
//     581c <agent 28b>                         agent
//     1a01312d00                               per_tx_cap   20_000_000
//     1a02faf080                               daily_cap    50_000_000
//     1a05265c00                               window_len   86_400_000
//     9f d8799f 581c<pol> 43544b4e 1901f4 1903e8 ff ff   token_caps=[AssetCap{pol,"TKN",500,1000}]
//     9f                                       spends = [
//       d8799f 40 40 1b000000e8d4a5fa60 1a00989680 ff   SpendRecord{"","",1_000_000_060_000,10_000_000}  (ADA)
//       d8799f 581c<pol> 43544b4e 1b000000e8d4a5fa60 19012c ff  SpendRecord{pol,"TKN",...,300}
//     ff
//     1a004c4b40                               min_principal 5_000_000
//     0a                                       max_spends    10
//     1b000001d1a94a2000                       expiry        2_000_000_000_000
//     d87980                                   kill          Constr 0 [] = False
//   ff
test datum_cbor_vector() {
  let d = sample_datum()
  cbor.serialise(d) == #"d8799f581c00000000000000000000000000000000000000000000000000000a0a581c5c48f601de2cf0a92d20f351e89704ec85871fafff310cebc7d80704581c00000000000000000000000000000000000000000000000000000b0b1a01312d001a02faf0801a05265c009fd8799f581c0000000000000000000000000000000000000000000000000000111143544b4e1901f41903e8ffff9fd8799f40401b000000e8d4a5fa601a00989680ffd8799f581c0000000000000000000000000000000000000000000000000000111143544b4e1b000000e8d4a5fa6019012cffff1a004c4b400a1b000001d1a94a2000d87980ff"
}
