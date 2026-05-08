use aiken/option
use aiken/collection/list
use aiken/collection/pairs
use aiken/collection/dict
use aiken/crypto.{blake2b_224}
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
  
}
use cardano/assets.{ PolicyId, }
use account/types.{
  AccountDatum,
  Account,
  Inbox,
  UtxoIntent,
  AccountRedeemer,
  IdMintRedeemer,
  MintId,
  KeyHash,
  SyncAccounts,
  SpendAccounts,
}
use account/utils.{burn_own_id, mint_own_id}
use account/validation.{validate_sync, validate_account_spends, input_to_utxo_intent}

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
          let minimum_fee = assets.quantity_of(output.value, fee_policy_id, fee_asset_name) >= sync_fee

          and{
            valid_owner,
            valid_id,
            nonce == 0,
            minimum_fee
          }
        }
        _ -> False
      }
    }
    
    let withdraw_redeemer = pairs.get_first(self.redeemers, Withdraw(Script(own_policy_id)))

    when withdraw_redeemer is {
      None -> {
        // There is another place where we allow burning and that is when
        // spending UtxoIntents
        let utxo_intent_burn_dict =
          self.inputs
            |> list.filter_map(_, fn (input) {
              input_to_utxo_intent(own_policy_id, input)
                |> option.map (fn (utxo_intent) {
                  Pair(utxo_intent.asset_name, -1)
                })
            })
            |> dict.from_pairs(_)

        let mint = assets.tokens(self.mint, own_policy_id)

        // Either burn or or mint but not both...
        // We can probably do both with `validation.output_to_account`
        if dict.is_empty(utxo_intent_burn_dict) {
          // allow minting accounts as normal; should only be burnable during sync
          expect MintId{..} = redeemer

          mint_own_id(redeemer, own_policy_id, self, valid_account_output)?
        } else {
          (mint == utxo_intent_burn_dict)?
        }
      }
      // defer to withdraw, which should only allow minting/burning UtxoIntents
      // during Spend or burning accounts during Sync
      Some(_) -> True
    }
  }

  spend(datum: Option<AccountDatum>, _redeemer: Data, own_input_ref: OutputReference, self: Transaction) -> Bool {
    expect Some(own_input) =
      list.find(
        self.inputs,
        fn (input) { input.output_reference == own_input_ref }
      )
    
    let withdraw_redeemer = pairs.get_first(self.redeemers, Withdraw(own_input.output.address.payment_credential))

    when withdraw_redeemer is {
      None -> {
        let sequencer_signed = list.has(self.extra_signatories, sequencer)
        when datum is {
          None -> sequencer_signed
          Some(Inbox{pub_key_hash, ..}) -> {
            and{
              sequencer_signed,
              list.has(self.extra_signatories, pub_key_hash),
            }
          }
          Some(UtxoIntent{..}) -> {
            and{
              sequencer_signed,
              burn_own_id(own_input_ref, self)
            }
          }
          _ -> False
        }
      }
      Some(_) -> True
    }
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
