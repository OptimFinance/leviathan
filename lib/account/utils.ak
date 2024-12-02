use aiken/bytearray
use aiken/cbor.{serialise}
use aiken/dict
use aiken/hash.{blake2b_256}
use aiken/list
use aiken/transaction.{
  DatumHash,
  InlineDatum,
  Input,
  Mint,
  NoDatum,
  Output,
  ScriptContext,
  Spend,
  Transaction,
  find_script_outputs
}
use aiken/transaction/credential.{
  ScriptCredential,
}
use aiken/transaction/value.{PolicyId, Value}
use account/types.{
  DataMap,
  Id,
  IdMintRedeemer,
  MintId,
  BurnId,
}

pub fn get_output_datum(output: Output, datums: DataMap) -> Data {
  when output.datum is {
    InlineDatum(data) -> data
    DatumHash(datum_hash) -> {
      expect Some(data) = dict.get(datums, datum_hash)
      data
    }
    NoDatum -> error "Script output missing datum"
  }
}

pub fn value_has_policy(value: Value, policy_id: PolicyId) {
  dict.size(value.tokens(value, policy_id)) > 0
}

pub fn id_to_string(id: Id) -> String {
  bytearray.to_hex(bytearray.concat(id.policy_id, id.asset_name))
}

pub fn input_has_own_id(input: Input) {
  expect ScriptCredential(script_hash) = input.output.address.payment_credential
  value_has_policy(input.output.value, script_hash)
}

// Passes if either all of this script's tokens are being burned, or each
// of our own outputs validates successfully
pub fn mint_own_id(
  redeemer: IdMintRedeemer,
  ctx: ScriptContext,
  extra_validate: fn(Output, Transaction) -> Bool
) -> Bool {
  let ScriptContext(tx_info, purpose) = ctx
  expect Mint(own_policy_id) = purpose
  let own_outputs = find_script_outputs(tx_info.outputs, own_policy_id)
  let own_mints = value.tokens(value.from_minted_value(tx_info.mint), own_policy_id)
  
  let validate_output = fn(output: Output, token_name_tail: ByteArray) {
    expect [(id_token_name, id_token_quantity)] =
      dict.to_list(value.tokens(output.value, own_policy_id))

    and{
      extra_validate(output, tx_info),
      bytearray.drop(id_token_name, 1) == token_name_tail,
      id_token_quantity == 1
    }
  }

  when redeemer is {
    MintId{ out_ref } -> {
      let token_name_tail =
        out_ref
          |> serialise
          |> blake2b_256
          |> bytearray.drop(1)

      and{
        list.all(own_outputs, validate_output(_, token_name_tail)),
        list.length(own_outputs) == dict.size(own_mints)
      }
    }
    BurnId ->
      // just check that tokens are actually burned, defer to spend validator
      list.all(dict.values(own_mints), fn(n) { n == -1 })
  }
}

pub fn burn_own_id(ctx: ScriptContext) -> Bool {
  let ScriptContext(tx_info, purpose) = ctx
  expect Spend(own_input_ref) = purpose
  expect Some(own_input) = 
    list.find(
      tx_info.inputs,
      fn (input) { input.output_reference == own_input_ref }
    )
  expect ScriptCredential(own_script_hash) = own_input.output.address.payment_credential
  expect Some(own_token_name) =
    value.tokens(own_input.output.value, own_script_hash)
      |> dict.keys
      |> list.head

  value.quantity_of(
    value.from_minted_value(tx_info.mint),
    own_script_hash,
    own_token_name
  ) == -1
}

pub fn id_spent(id: Id, inputs: List<Input>) -> Bool {
  list.any(
    inputs,
    fn(input) {
      value.quantity_of(input.output.value, id.policy_id, id.asset_name) > 0
    }
  )
}
