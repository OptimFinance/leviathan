use aiken/collection/list
use aiken/collection/pairs
use aiken/collection/dict.{Dict}
use aiken/crypto.{blake2b_224}
use aiken/option
use cardano/transaction.{
  Input,
  Output,
  OutputReference,
  Transaction,
  InlineDatum,
  Withdraw,
}
use cardano/address.{
  Address,
  Credential,
  Script,
  VerificationKey,
}
use cardano/assets.{AssetName, PolicyId, Value}
use account/types.{
  AccountDatum,
  Account,
  Inbox,
  AccountRedeemer,
  IdMintRedeemer,
  MintId,
  KeyHash,
  SyncAccounts,
  SpendAccounts,
}
use account/utils.{mint_own_id}
use refactor.{validate_account_spends}

pub fn validate_sync(
  sequencer: KeyHash,
  fee_policy_id: PolicyId,
  fee_asset_name: AssetName,
  sync_fee: Int,
  account_script: Credential,
  inputs: List<Input>,
  outputs: List<Output>,
  mint: Value,
) -> Bool {
  expect Script(account_script_hash) = account_script
  let get_owner = fn(output: Output) {
    let credential = output.address.payment_credential
    
    if credential == account_script {
      expect InlineDatum(datum) = output.datum
      if datum is Account{pub_key_hash, ..}: AccountDatum {
        Some(pub_key_hash)
      } else if datum is Inbox{pub_key_hash, ..}: AccountDatum {
        Some(pub_key_hash)
      } else {
        None
      }
    } else {
      when credential is {
        VerificationKey(pkh) -> if pkh == sequencer {
          None 
        } else {
          Some(pkh)
        }
        _ -> None
      }
    }
  }

  let in_value_map: Dict<ByteArray, Value> = list.foldl(
    inputs,
    dict.empty,
    fn (input, prev: Dict<ByteArray, Value>) {
      let owner = get_owner(input.output)
      let value = assets.add(input.output.value, fee_policy_id, fee_asset_name, -sync_fee)
      when owner is {
        Some(pkh) ->
          when dict.get(prev, pkh) is {
            Some(prev_entry) -> dict.insert(prev, pkh, assets.merge(prev_entry, value))
            None -> dict.insert(prev, pkh, value)
          }
        None -> prev
      }
    }
  )

  let out_value_map = list.foldl(
    outputs,
    dict.empty,
    fn (output, prev) {
      let owner = get_owner(output)
      when owner is {
        Some(pkh) ->
          when dict.get(prev, pkh) is {
            Some(prev_entry) -> dict.insert(prev, pkh, assets.merge(prev_entry, output.value))
            None -> dict.insert(prev, pkh, output.value)
          }
        None -> prev
      }
    }
  )

  let account_mints = assets.tokens(mint, account_script_hash)

  expect list.all(dict.values(account_mints), fn (value) { value == -1 })

  expect out_value_map_with_burns, _remaining_outputs <- list.foldl2(
    inputs,
    out_value_map,
    outputs,
    fn (input, out_value_map, remaining_outputs, return) {
      if input.output.address.payment_credential == account_script {
        expect InlineDatum(datum) = input.output.datum
        if datum is Account{id, pub_key_hash, ..}: AccountDatum {
          when dict.get(account_mints, id) is {
            Some(-1)  -> {
              expect Some(owner_value) = dict.get(out_value_map, pub_key_hash) 
              return(
                dict.insert(
                  out_value_map,
                  pub_key_hash,
                  owner_value |> assets.add(account_script_hash, id, -1)
                ),
                remaining_outputs
              )
            }
            None -> {
              expect [output, ..new_remaining_outputs] = list.drop_while(
                remaining_outputs,
                fn (output) { output.address.payment_credential != account_script }
              )

              expect and {
                output.datum == input.output.datum,
                dict.to_pairs(assets.tokens(output.value, account_script_hash)) == [Pair(id, 1)]
              }

              return(out_value_map, new_remaining_outputs)
            }
            _ -> fail "Only burning accounts is permitted during sync (also impossible)"
          }
        } else {
          return(out_value_map, remaining_outputs)
        }
      } else {
        return(out_value_map, remaining_outputs)
      }
    }
  )

  in_value_map == out_value_map_with_burns
}

validator account(
  sequencer: KeyHash,
  fee_policy_id: ByteArray,
  fee_asset_name: ByteArray,
  sync_fee: Int
) {
  mint(redeemer: IdMintRedeemer, own_policy_id: PolicyId, self: Transaction) -> Bool {
    let valid_account_output = fn(output: Output, self: Transaction) {
      expect datum: AccountDatum = {
        expect InlineDatum(datum) = output.datum
        datum
      }
      when datum is {
        Account{verification_key, pub_key_hash, id, nonce} -> {
          let valid_owner = and {
            blake2b_224(verification_key) == pub_key_hash,
            list.has(self.extra_signatories, pub_key_hash)
          }

          let valid_id = dict.to_pairs(assets.tokens(output.value, own_policy_id)) == [Pair(id, 1)]

          and{
            valid_owner,
            valid_id,
            nonce == 0
          }
        }
        _ -> False
      }
    }
    
    let withdraw_redeemer = pairs.get_first(self.redeemers, Withdraw(Script(own_policy_id)))

    when withdraw_redeemer is {
      None -> {
        // allow minting accounts as normal; should only be burnable during sync
        expect MintId{..} = redeemer

        mint_own_id(redeemer, own_policy_id, self, valid_account_output)
      }
      // defer to withdraw, which should only allow minting/burning UtxoIntents
      // during Spend or burning accounts during Sync
      Some(_) -> True
    }
  }

  spend(_datum: Option<AccountDatum>, _redeemer: Data, own_input_ref: OutputReference, self: Transaction) -> Bool {
    expect Some(own_input) =
      list.find(
        self.inputs,
        fn (input) { input.output_reference == own_input_ref }
      )
    
    pairs.get_first(self.redeemers, Withdraw(own_input.output.address.payment_credential)) |> option.is_some
  }

  withdraw(redeemer: AccountRedeemer, account: Credential, self: Transaction) -> Bool {
    expect list.has(self.extra_signatories, sequencer)
    when redeemer is {
      SyncAccounts ->
        validate_sync(
          sequencer,
          fee_policy_id,
          fee_asset_name,
          sync_fee,
          account,
          self.inputs,
          self.outputs,
          self.mint
        )?
      SpendAccounts(spends) -> {
        validate_account_spends(
          spends,
          account,
          fee_policy_id,
          fee_asset_name,
          self.inputs,
          self.outputs,
          self.mint
        )?
      }
    }
  }

  publish(_redeemer: Data, _certificate: Data, _self: Data) -> Bool {
    True
  }
}
