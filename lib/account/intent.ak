use aiken/cbor.{serialise}
use aiken/crypto.{VerificationKey, verify_ed25519_signature}
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
  expect Account{id, verification_key, ..}: AccountDatum = {
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
    } else if (length < 0x18) {
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

  and{
    (intent.account == id)?,
    verify_ed25519_signature(verification_key, message, signature)?,
  }
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
    let payload = serialise(intent)
    let length = bytearray.length(payload)
    let header = if (length > 256) {
      bytearray.concat(#"59", bytearray.from_int_big_endian(length, 2))
    } else if (length < 0x18) {
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

  and{
    (intent.account == asset_name)?,
    verify_ed25519_signature(v_key, message, signature)?,
  }
}

pub fn validate_payload(
  payload: ByteArray,
  protected: ByteArray,
  external_aad: ByteArray,
  hashed: Bool,
  v_key: VerificationKey,
  signature: ByteArray,
) -> Bool {
  let payload_length = bytearray.length(payload)
  let header = if (payload_length > 256) {
      bytearray.concat(#"59", bytearray.from_int_big_endian(payload_length, 2))
  } else if (payload_length < 0x18) {
      bytearray.from_int_little_endian(0x40 + payload_length, 1)
  } else {
      bytearray.concat(#"58", bytearray.from_int_big_endian(payload_length, 1))
  }

  //let payload = if (indefinite_bytestring) {
  //  serialise(serialise(intent))
  //} else {
  //  let payload = serialise(intent)
  //  let length = bytearray.length(payload)
  //  let header = if (length > 256) {
  //    bytearray.concat(#"59", bytearray.from_int_big_endian(length, 2))
  //  } else if (length < 0x18) {
  //    bytearray.from_int_little_endian(0x40 + length, 1)
  //  } else {
  //    bytearray.concat(#"58", bytearray.from_int_big_endian(length, 1))
  //  }
  //  header |> bytearray.concat(payload)
  //}
  let message = 
    #"84" |> // `Sig_structure` is a list of 4 items
    bytearray.concat(#"6a5369676e617475726531") |> // @"Signature1"
    bytearray.concat(protected) |> // protected headers map, just taken from the user
    bytearray.concat(external_aad) |> // additional application data, should just be the empty bytestring
    bytearray.concat(bytearray.concat(header, payload)) |>
    if (hashed) { crypto.blake2b_224 } else { fn (x) {x} }

  verify_ed25519_signature(v_key, message, signature)?
  //and{
  //  (intent.account == asset_name)?,
  //}
}

test hoho() {
  let intent = Intent {
    account: #"0038ecdffc6308519db115c3d74e0963ded8ee542843c8d52cb64a64047fbf0e",
    nonce: 0,
    fee: 1000000,
    payload: SendIntent {
      recipient: #"0138ecdffc6308519db115c3d74e0963ded8ee542843c8d52cb64a64047fbf0e",
      assets: [Pair("", [Pair("", 10000000)])]
    },
    partial: False
  }

  //let signed_intent = SignedIntent {
  //  intent,
  //  protected: #"a201276761646472657373581d605b9ab6d43d9e2c14f07e6ac1a03d286a2f22687206136335a8c0196b",
  //  external_aad: #"40",
  //  hashed: False,
  //  indefinite_bytestring: False,
  //  signature: #"9f23d4c103d603f96fa6ed9ee9f20c0997eb1817a52d77e8b7141a673461a675f311b9965ebb8ae02885bc0d892c96ab599217b64d34164fe4874db293fd130b"
  //}

  trace cbor.diagnostic(cbor.serialise(intent))

  // 

  // D8799F58200038ECDFFC6308519DB115C3D74E0963DED8EE542843C8D52CB64A64047FBF0E001A000F4240D8799F58200138ECDFFC6308519DB115C3D74E0963DED8EE542843C8D52CB64A64047FBF0EA140A1401A00989680FFD87980FF

  //let result = haha(
  //#"d8799f58200038ecdffc6308519db115c3d74e0963ded8ee542843c8d52cb64a64047fbf0e001a000f4240d8799f58200138ecdffc6308519db115c3d74e0963ded8ee542843c8d52cb64a64047fbf0ea140a1401a00989680ffd87980ff",
  //#"a201276761646472657373581d607b1ea646b1c87d099d3b3491c4a1a335b0aedb300d14f216b8a43015",
  //#"40",
  //False,
  //#"7a2369855bfc16a0bedd0f0f5915ebed4f3f3027154baa6fe4b4b732c24c5941",
  //#"9b84b8c6a076e9a8a394965e8c064085863bffa88a721a5c6e20e8bb3c9fff5a93a44a5dc3a005c94082071dbff4579d4e536aedc4e034e4542932edf9b71908"
  //)

  let result = validate_payload(
  #"d8799f5820002b5a230f3f00b630d813628efd857642ab0f742ca322c0173bfc6316143699001a000f4240d8799f5820012b5a230f3f00b630d813628efd857642ab0f742ca322c0173bfc6316143699a140a1401a00989680ffd87980ff",
  #"582aa201276761646472657373581d60cb5340415fe60569dddab78ea04b4e373c22e46f4fd2cfce2b662115",
  #"40",
  False,
  #"7071204d667cb091c48bcae466eeb503968d00ba326d81be4257964ebe1f5d1a",
  #"8c9191dba554dfa1d6ec8dc946922aa75bec7790c7a82f897e8b475d461449dd2781d706c301f0e0f9398c45d5f55ffabb1b7031c51180354f69f0ec6bef5206"
  )

  result
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
  trace(cbor.serialise(OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
    output_index: 1,
  }))
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
