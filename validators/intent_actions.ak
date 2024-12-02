use aiken/list
use aiken/bytearray
use aiken/dict.{Dict}
use aiken/option
use aiken/string
use aiken/cbor.{serialise}
use aiken/hash.{blake2b_256}
use aiken/transaction.{Input, Output, ScriptContext, WithdrawFrom}
use aiken/transaction/credential.{Inline, verify_signature}
use aiken/transaction/value.{MintedValue, Value}
use account/types.{
  AccountAddress,
  AccountDatum,
  Action,
  DataMap,
  IdAddress,
  Intent,
  IntentActionsRedeemer,
  MoveTokens,
  RawAddress,
  VirtualAddress,
  ZeroAddress
}
use account/utils.{get_output_datum, id_spent}

fn assume_ordered(_x, _y) { Less }

fn valid_intent(intent: Intent, inputs: List<Input>, datums: DataMap) {
  expect Some(account_input) =
    list.find(
      inputs,
      fn (input) { 
        expect datum: AccountDatum = get_output_datum(input.output, datums)
        datum.account_id == intent.account_id
      }
    ) 
  expect account_datum: AccountDatum = get_output_datum(account_input.output, datums)

  let tx_prefix = #"84A50081825820000000000000000000000000000000000000000000000000000000000000000000018182581D610000000000000000000000000000000000000000000000000000000000020007"
  let tx_infix = #"0E81581C"
  let tx_suffix = #"A0F5F6"

  let wrap_metadata_hash = fn(data) {
    tx_prefix 
      // hash the metadata data, serialise the hash, and put it in the
      // transaction body at key `7`
      |> bytearray.concat(serialise(blake2b_256(serialise(data))))
      |> bytearray.concat(tx_infix)
      // add the owner's key hash to the required signatories list
      |> bytearray.concat(account_datum.owner)
      |> bytearray.concat(tx_suffix)
  }

  // TODO: profile and compare vs. just serialising each key/value and splicing
  // together a CBOR map
  let data_hash =
    dict.new()
      |>
        dict.insert(
          327,
          dict.from_ascending_list(
            [ ("account_asset_name", bytearray.to_hex(intent.account_id.asset_name))
            , ("account_nonce", string.from_int(intent.nonce))
            , ("account_policy_id", bytearray.to_hex(intent.account_id.policy_id))
            , ("app_asset_name", bytearray.to_hex(intent.app_id.asset_name))
            , ("app_policy_id", bytearray.to_hex(intent.app_id.policy_id))
            , ("fee", string.from_int(intent.fee))
            , ("header", intent.header)
            , ("payload", intent.payload)
            ],
            assume_ordered
          ),
          assume_ordered
        )
      |> wrap_metadata_hash
      |> blake2b_256

  verify_signature(account_datum.verification_key, data_hash, intent.signature)
}

fn valid_action(action: Action, reference_inputs: List<Input>) {
  id_spent(action.app_id, reference_inputs)?
}

fn ledger_balanced(
  actions: List<Action>,
  inputs: List<Input>,
  outputs: List<Output>,
  mint: MintedValue,
  tx_fee: Int,
  fee_payer: VirtualAddress
) -> Bool {
  let compare_data =
    fn(a: Data, b: Data) {
      bytearray.compare(serialise(a), serialise(b))
    }

  // TODO: profile and see if comparing constructors before serialising
  // actually helps much
  let compare_virtual_address =
    fn(a: VirtualAddress, b: VirtualAddress) {
      when (a, b) is {
        (ZeroAddress, ZeroAddress) -> Equal
        (ZeroAddress, _) -> Less
        (AccountAddress(id_a), AccountAddress(id_b)) -> compare_data(id_a, id_b)
        (AccountAddress(_), _) -> Less
        (IdAddress(id_a), IdAddress(id_b)) -> compare_data(id_a, id_b)
        (IdAddress(_), _) -> Less
        (RawAddress(cred_a), RawAddress(cred_b)) -> compare_data(cred_a, cred_b)
        (RawAddress(_), _) -> Less
      }
    }

  let get_output_address =
    fn(output: Output) -> VirtualAddress {
      RawAddress(output.address.payment_credential)
    }

  let update_ledger =
    fn(output: Output, map: Dict<VirtualAddress, Value>) {
      let virtual_address = get_output_address(output)
      let current_value = option.or_else(dict.get(map, virtual_address), value.zero())

      dict.insert(
        map,
        virtual_address,
        value.merge(current_value, output.value),
        compare_virtual_address
      )
    }

  let input_value_map =
    list.foldl(
      list.map(inputs, fn(input) { input.output }),
      dict.new()
        |> dict.insert(ZeroAddress, value.zero(), compare_virtual_address),
      update_ledger
    )

  let value_delta_map =
    list.foldl(
      actions,
      dict.new() |> dict.insert(fee_payer, value.from_lovelace(-tx_fee), compare_virtual_address),
      fn(action, map) {
        let MoveTokens(_, tokens, sender, recipient) = action
        let current_sender_value = option.or_else(dict.get(map, sender), value.zero())
        let current_recipient_value = option.or_else(dict.get(map, recipient), value.zero())

        map
          |>
            dict.insert(
              sender,
              value.merge(current_sender_value, value.negate(tokens)),
              compare_virtual_address
            )
          |>
            dict.insert(
              recipient,
              value.merge(current_recipient_value, tokens),
              compare_virtual_address
            )
      }
    )

  let output_value_map =
    list.foldl(
      outputs,
      dict.new()
        |> dict.insert(ZeroAddress, value.from_minted_value(mint), compare_virtual_address),
      update_ledger
    )

  output_value_map == 
    dict.union_with(
      input_value_map,
      value_delta_map, 
      fn(_k, v1, v2) { Some(value.merge(v1, v2)) },
      compare_virtual_address
    )
}

validator() {
  fn withdraw(redeemer: IntentActionsRedeemer, ctx: ScriptContext) -> Bool {
    let ScriptContext(tx_info, purpose) = ctx
    expect WithdrawFrom(Inline(_own_credential)) = purpose
    let IntentActionsRedeemer(intents, actions) = redeemer

    and{
      list.all(intents, valid_intent(_, tx_info.inputs, tx_info.datums)),
      list.all(actions, valid_action(_, tx_info.reference_inputs))
    }
  }
}
