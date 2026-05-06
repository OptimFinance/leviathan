use aiken/cbor.{serialise}
use aiken/crypto.{verify_ed25519_signature}
use aiken/primitive/bytearray
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}
use cardano/address.{Address, Script}
use cardano/assets
use account/types.{
  Account,
  AccountDatum,
  AccountOutput,
  AccountData,
  Intent,
  SignedIntent,
  SendIntent,
}

pub fn valid_intent(intent: SignedIntent, account_input: Input) {
  expect Account{id, verification_key, pub_key_hash, nonce}: AccountDatum = {
    expect InlineDatum(datum) = account_input.output.datum
    datum
  }

  validate_signed_intent(
  intent,
  AccountOutput {
    policy_id: "",
    value: assets.zero,
    asset_name: id,
    data: AccountData{
      v_key: verification_key,
      pub_key_hash: pub_key_hash,
      nonce,
    }
  })
}

pub fn validate_signed_intent(
  SignedIntent{
    intent,
    protected,
    external_aad,
    hashed,
    indefinite_bytestring,
    signature
  }: SignedIntent,
  AccountOutput{asset_name, data: AccountData{v_key, ..}, ..}: AccountOutput,
) -> Bool {
  let payload = if (indefinite_bytestring) {
    serialise(serialise(intent))
  } else {
    let payload = serialise(intent) |> if (hashed) { crypto.blake2b_224 } else { fn (x) {x} }
    let length = bytearray.length(payload)
    let header = if (length > 255) {
      bytearray.concat(#"59", bytearray.from_int_big_endian(length, 2))
    } else if (length < 0x18) {
      bytearray.from_int_little_endian(0x40 + length, 1)
    } else {
      bytearray.concat(#"58", bytearray.from_int_big_endian(length, 1))
    }
    bytearray.concat(header, payload)
  }
  let message = 
    #"84" |> // `Sig_structure` is a list of 4 items
    bytearray.concat(#"6a5369676e617475726531") |> // @"Signature1"
    bytearray.concat(protected) |> // protected headers map, just taken from the user
    bytearray.concat(external_aad) |> // additional application data, should just be the empty bytestring
    bytearray.concat(payload)

  and{
    (intent.account == asset_name)?,
    verify_ed25519_signature(v_key, message, signature)?,
  }
}

test signature_valid() {
  let account_script = #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  let intent = Intent {
    account: #"ea13d307d664c79dd908ac040ccff8cfab79b1d99740b249db6df0a7d0686abe",
    nonce: 2,
    fee: 1500000,
    payload: SendIntent {
      recipient: #"9604ff3c3c7b3d905c3b1dac703b0f91a7047298881b22684573c688b3862159",
      assets: [
        Pair(#"3773a3d5baf127126cc4d473d968c683ebc0845cc4554cbf6e48d371",
          [Pair(#"744f414441", 5000000)]
        )
      ]
    },
    partial: False
  }
  valid_intent(
    SignedIntent {
      intent,
      protected: #"5846a201276761646472657373583900bfef37929d1741059cb84e83a7869ffa6c9a9728b3da0421de904eff8f4eab9afe5eeb29c8ab65a26824487ed037ccf9ad9ce12e90e29508",
      external_aad: #"40",
      hashed: True,
      indefinite_bytestring: False,
      signature: #"62de9e570875b4e88dbd4a752e2c3bcf2f79876bea6524034dcfadd2a8785f5fe923b51e9e7ae904e14f144205c83e4b94c12ccddc1e96e100068d5b02b90706"
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
          id: #"ea13d307d664c79dd908ac040ccff8cfab79b1d99740b249db6df0a7d0686abe",
          pub_key_hash: #"bfef37929d1741059cb84e83a7869ffa6c9a9728b3da0421de904eff",
          verification_key: #"a3c6736375528a46c9d9b0fcff59f355ec8eba04021b3cbffbf89db2a2657aba",
          nonce: 0,
        }),
        reference_script: None,
      }
    }
  )
}
