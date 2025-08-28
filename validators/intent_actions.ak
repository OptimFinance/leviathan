use aiken/collection/list
use aiken/collection/dict.{Dict}
use aiken/option
use aiken/cbor.{serialise}
use aiken/crypto.{blake2b_256, verify_ed25519_signature}
use cardano/transaction.{Input, Output, Transaction, }
use cardano/address.{Credential}
use cardano/assets.{Value}
use account/types.{
  AccountDatum,
  Action,
  DataMap,
  Intent,
  IntentActionsRedeemer,
  MoveTokens,
  RawAddress,
  SignedIntent,
  VirtualAddress,
  ZeroAddress
}
use account/utils.{get_output_datum, id_spent}

fn valid_intent(SignedIntent{intent, signature}: SignedIntent, inputs: List<Input>, datums: DataMap) {
  expect Some(account_input) =
    list.find(
      inputs,
      fn (input) { 
        expect datum: AccountDatum = get_output_datum(input.output, datums)

        // TODO: verify this is an actual account input
        datum.account_id == intent.account_id
      }
    ) 
  expect account_datum: AccountDatum = get_output_datum(account_input.output, datums)

  let data_hash = serialise(intent) |> blake2b_256

  verify_ed25519_signature(account_datum.verification_key, data_hash, signature)?
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
      list.all(intents, valid_intent(_, self.inputs, self.datums))?,
      list.all(actions, valid_action(_, self.reference_inputs))?
    }
  }
}
