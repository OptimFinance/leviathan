use aiken/cbor.{serialise}
use aiken/crypto.{verify_ed25519_signature}
use aiken/primitive/bytearray
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}
use cardano/address.{Address, Script}
use cardano/assets
use account/types.{
  Account,
  AccountDatum,
  Intent,
  SignedIntent,
  SendIntent,
}

pub fn valid_intent(
  SignedIntent{
    intent,
    protected,
    external_aad,
    hashed,
    indefinite_bytestring,
    signature
  }: SignedIntent,
  account_input: Input,
) {
  expect Account{verification_key, ..}: AccountDatum = {
    expect InlineDatum(datum) = account_input.output.datum
    datum
  }

  let payload = if (indefinite_bytestring) {
    serialise(serialise(intent))
  } else {
    let payload = serialise(intent)
    let length = bytearray.length(payload)
    let header = if (length > 256) {
      bytearray.concat(#"59", bytearray.from_int_big_endian(length, 2))
    } else if (length <= 16) {
      bytearray.from_int_little_endian(0x40 + length, 1)
    } else {
      bytearray.concat(#"58", bytearray.from_int_big_endian(length, 1))
    }
    header |> bytearray.concat(payload)
  }
  let message = 
    #"84" |> // `Sig_structure` is a list of 4 items
    bytearray.concat(#"6a5369676e617475726531") |> // @"Signature1"
    bytearray.concat(protected) |> // protected headers map, just taken from the user
    bytearray.concat(external_aad) |> // additional application data, should just be the empty bytestring
    bytearray.concat(payload) |>
    if (hashed) { crypto.blake2b_224 } else { fn (x) {x} }

  verify_ed25519_signature(verification_key, message, signature)?
}

test signature_valid() {
  let account_script = #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  let intent = Intent {
    account: "",
    nonce: 0,
    fee: 0,
    payload: SendIntent {
      recipient: "",
      assets: []
    },
    partial: False
  }
  trace(cbor.serialise(intent))
  valid_intent(
    SignedIntent {
      intent,
      protected: #"582aa201276761646472657373581d612042e66ff84b5b5cbfc64cc769682eb9ea55ec8a186c2fbe49c8dc72",
      external_aad: #"40",
      hashed: False,
      indefinite_bytestring: False,
      signature: #"4ea96350e1ff28f3b049673f1d0a0c9520a36f5d6e838f56de2f148bd328a9f6898958ca80c02d7c0c5d1e49b7eca2a5c21008983a2e0813fc8cc593aad5b80f"
    },
    Input {
      output_reference: OutputReference {
        transaction_id: #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        output_index: 0
      },
      output: Output {
        address: Address{
          payment_credential: Script(account_script),
          stake_credential: None
        },
        value: assets.from_asset_list([Pair(account_script, [Pair("", 1)])]),
        datum: InlineDatum(Account {
          id: "",
          pub_key_hash: #"2042e66ff84b5b5cbfc64cc769682eb9ea55ec8a186c2fbe49c8dc72",
          verification_key: #"c1732fa372ce6dcea07a0ff842a1988bc5989faba463bca5aee3d5473e35c089",
          nonce: 0,
        }),
        reference_script: None,
      }
    }
  )
}
