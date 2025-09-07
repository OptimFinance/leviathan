use aiken/collection/list
use aiken/collection/dict.{Dict}
use aiken/option
use aiken/cbor.{serialise}
use aiken/crypto.{blake2b_224, verify_ed25519_signature}
use aiken/primitive/bytearray
use cardano/transaction.{InlineDatum, Input, Output, OutputReference, Transaction, }
use cardano/address.{Credential}
use cardano/assets.{Value}
use account/types.{
  AccountDatum,
  Action,
  DataMap,
  Id,
  Intent,
  IntentActionsRedeemer,
  MoveTokens,
  RawAddress,
  SignedIntent,
  VirtualAddress,
  ZeroAddress
}
use account/utils.{get_output_datum, id_spent}

fn valid_intent(SignedIntent{
  intent,
  protected,
  external_aad,
  hashed,
  indefinite_bytestring,
  signature
}: SignedIntent, reference_inputs: List<Input>, datums: DataMap) {
  expect Some(account_input) =
    list.find(
      reference_inputs,
      fn (input) { 
        expect datum: AccountDatum = get_output_datum(input.output, datums)

        // TODO: verify this is an actual account input
        datum.account_id == intent.account_id
      }
    ) 
  expect account_datum: AccountDatum = get_output_datum(account_input.output, datums)

  let payload = if (indefinite_bytestring) {
    serialise(serialise(intent))
  } else {
    let payload = serialise(intent)
    let length = bytearray.length(payload)
    let header = if (length > 256) {
      #"59" |> bytearray.concat(bytearray.from_int_big_endian(length, 2))
    } else {
      #"58" |> bytearray.concat(bytearray.from_int_big_endian(length, 1))
    }
    header |> bytearray.concat(payload)
  }
  let message = 
    #"84" |> // `Sig_structure` is a list of 4 items
    bytearray.concat(#"6a5369676e617475726531") |> // @"Signature1"
    bytearray.concat(protected) |> // protected headers map, just taken from the user
    bytearray.concat(external_aad) |> // additional application data, should just be the empty bytestring
    bytearray.concat(payload) |>
    if (hashed) { blake2b_224 } else { fn (x) {x} }

  verify_ed25519_signature(account_datum.verification_key, message, signature)?
}

fn valid_action(action: Action, reference_inputs: List<Input>) {
  id_spent(action.app_id, reference_inputs)?
}

pub fn ledger_balanced(
  actions: List<Action>,
  inputs: List<Input>,
  outputs: List<Output>,
  mint: Value,
  tx_fee: Int,
  fee_payer: VirtualAddress
) -> Bool {
  let get_output_address =
    fn(output: Output) -> VirtualAddress {
      RawAddress(output.address.payment_credential)
    }

  let update_ledger =
    fn(output: Output, map: Dict<VirtualAddress, Value>) {
      let virtual_address = get_output_address(output)
      let current_value = option.or_else(dict.get(map, cbor.serialise(virtual_address)), assets.zero)

      dict.insert(
        map,
        cbor.serialise(virtual_address),
        assets.merge(current_value, output.value),
      )
    }

  let input_value_map =
    list.foldl(
      list.map(inputs, fn(input) { input.output }),
      dict.empty
        |> dict.insert(_, cbor.serialise(ZeroAddress), assets.zero),
      update_ledger
    )

  let value_delta_map =
    list.foldl(
      actions,
      dict.empty |> dict.insert(_, cbor.serialise(fee_payer), assets.from_lovelace(-tx_fee)),
      fn(action, map) {
        let MoveTokens{tokens: tokens_list, sender, recipient, ..} = action
        let current_sender_value = option.or_else(dict.get(map, cbor.serialise(sender)), assets.zero)
        let current_recipient_value = option.or_else(dict.get(map, cbor.serialise(recipient)), assets.zero)
        let tokens = assets.from_asset_list(tokens_list)

        map
          |>
            dict.insert(
              _,
              cbor.serialise(sender),
              assets.merge(current_sender_value, assets.negate(tokens)),
            )
          |>
            dict.insert(
              _,
              cbor.serialise(recipient),
              assets.merge(current_recipient_value, tokens),
            )
      }
    )

  let output_value_map =
    list.foldl(
      outputs,
      dict.empty
        |> dict.insert(_, cbor.serialise(ZeroAddress), mint),
      update_ledger
    )

  output_value_map == 
    dict.union_with(
      input_value_map,
      value_delta_map, 
      fn(_k, v1, v2) { Some(assets.merge(v1, v2)) },
    )
}

validator intent_actions() {
  withdraw(redeemer: IntentActionsRedeemer, _account: Credential, self: Transaction) -> Bool {
    let IntentActionsRedeemer{intents, actions} = redeemer

    and{
      list.all(intents, valid_intent(_, self.reference_inputs, self.datums))?,
      list.all(actions, valid_action(_, self.reference_inputs))?
    }
  }
}

test signature_valid() {
  valid_intent(
    SignedIntent {
      intent: Intent {
        account_id: Id {
          policy_id: #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          asset_name: ""
        },
        app_id: Id {
          policy_id: #"22222222222222222222222222222222222222222222222222222222",
          asset_name: "",
        },
        header: "",
        nonce: 0,
        fee: 0,
        payload: "PAY 0 TO XXX"
      },
      protected: #"5846a20127676164647265737358390094dd9d0961470f93c482af7b827ba5f943f230062bf89e09f8fba10f34fd67830a9a0a131039bb9769789482c0970f781dd952b89d7f3c44",
      external_aad: #"40",
      hashed: False,
      indefinite_bytestring: False,
      signature: #"53c55181ebecb72e28e6291cff3c985288228fd847fd1d5c263959437ef44f1e4776b2328a273f61477405f5f1171b699e3d5f2b30799881563c5ee1c7dfd708"
    },
    [
      Input {
        output_reference: OutputReference {
          transaction_id: #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          output_index: 0
        },
        output: Output {
          address: address.from_verification_key(#"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
          value: assets.zero,
          datum: InlineDatum(AccountDatum {
            account_id: Id {
              policy_id: #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
              asset_name: ""
            },
            owner: #"c21687393b92c103be1e32be7922e1808a7a17650be2306c9b2fc31b",
            verification_key: #"6528e6105123ab805e9248c5a6381637347adfbff7ee15fed560614d6d352d2d",
            nonce: 0,
            intent_hash: "",
          }),
          reference_script: None,
        }
      }
    ],
    dict.from_pairs([])
  )
}
