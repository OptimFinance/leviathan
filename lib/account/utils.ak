use aiken/primitive/bytearray
use aiken/cbor.{serialise}
use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{blake2b_256}
use cardano/transaction.{
  DatumHash,
  InlineDatum,
  Input,
  NoDatum,
  Output,
  OutputReference,
  Transaction,
  find_script_outputs
}
use cardano/address.{Script}
use cardano/assets.{PolicyId, Value}
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
  dict.size(assets.tokens(value, policy_id)) > 0
}

pub fn id_to_string(id: Id) -> String {
  bytearray.to_hex(bytearray.concat(id.policy_id, id.asset_name))
}

pub fn input_has_own_id(input: Input) {
  expect Script(script_hash) = input.output.address.payment_credential
  value_has_policy(input.output.value, script_hash)
}

// Passes if either all of this script's tokens are being burned, or each
// of our own outputs validates successfully
pub fn mint_own_id(
  redeemer: IdMintRedeemer,
  own_policy_id: PolicyId,
  tx: Transaction,
  extra_validate: fn(Output, Transaction) -> Bool
) -> Bool {
  let own_outputs = find_script_outputs(tx.outputs, own_policy_id)
  let own_mints = assets.tokens(tx.mint, own_policy_id)
  
  let validate_output = fn(output: Output, token_name_tail: ByteArray) {
    expect [Pair(id_token_name, id_token_quantity)] =
      dict.to_pairs(assets.tokens(output.value, own_policy_id))

    and{
      extra_validate(output, tx),
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

pub fn burn_own_id(own_input_ref: OutputReference, tx: Transaction) -> Bool {
  expect Some(own_input) = 
    list.find(
      tx.inputs,
      fn (input) { input.output_reference == own_input_ref }
    )
  expect Script(own_script_hash) = own_input.output.address.payment_credential
  expect Some(own_token_name) =
    assets.tokens(own_input.output.value, own_script_hash)
      |> dict.keys
      |> list.head

  assets.quantity_of(
    tx.mint,
    own_script_hash,
    own_token_name
  ) == -1
}

pub fn id_spent(id: Id, inputs: List<Input>) -> Bool {
  list.any(
    inputs,
    fn(input) {
      assets.quantity_of(input.output.value, id.policy_id, id.asset_name) > 0
    }
  )
}
