use aiken/builtin
use aiken/collection/list
use aiken/collection/pairs
use aiken/collection/dict.{Dict}
use aiken/crypto.{blake2b_224}
use aiken/math/rational
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
  SpendRedeemer, UtxoIntent,
  AccountRedeemer,
  AssetList,
  ExchangeIntent,
  IdMintRedeemer,
  MintId,
  Intent,
  IntentSatisfaction, KeyHash,
  NoncedIntent,
  AccountSpend,
  SendIntent,
  SpentIntent,
  SyncAccounts,
  SpendAccounts,
}
use account/utils.{mint_own_id}
use account/intent.{valid_intent}
use refactor.{validate_account_spends}

type OwnerAccumulator {
  input: Option<Input>,
  output: Option<Output>,
  gain: Value,
  loss: Value,
}

pub fn validate_sync(
  sequencer: KeyHash,
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
      let value = assets.add(input.output.value, "", "", -sync_fee)
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

fn merge(a: Dict<AssetName, OwnerAccumulator>, b: Dict<AssetName, OwnerAccumulator>) {
  dict.union_with(a, b, fn (_key, a, b, keep, _discard) {
    keep(OwnerAccumulator {
      input: option.choice([b.input, a.input]),
      output: option.choice([b.output, a.output]),
      gain: assets.merge(a.gain, b.gain),
      loss: assets.merge(a.loss, b.loss),
    })
  })
}

fn scale(assets: AssetList, (num, denom): (Int, Int)) {
  list.map(
    assets,
    fn (Pair(policy_id, tokens)) {
      Pair(
        policy_id,
        list.map(
          tokens,
          fn (Pair(token_name, quantity)) {
            Pair(token_name, quantity * num / denom)
          }
        )
      )
    }
  )
}

fn validate_intent(
  account_script: Credential,
  input: Input,
  account_id: ByteArray,
  inputs: List<Input>,
) {
  fn (
    redeemer: SpendRedeemer,
    acc: (Dict<AssetName, Int>, Dict<AssetName, OwnerAccumulator>),
    continuing_outputs: List<Output>,
    return
  ) {
    expect Script(account_script_hash) = account_script
    let (satisfaction, continuing_datum, continuing_id) = when redeemer.satisfaction is {
      Some(IntentSatisfaction{ num, denom }) -> {
        expect Some(s) = rational.new(num, denom)
        expect Some(output) = list.head(continuing_outputs)
        let continuing_id = assets.tokens(output.value, account_script_hash)
        expect UtxoIntent{..} as utxo_intent_datum: AccountDatum = {
          expect InlineDatum(datum) = output.datum
          datum
        }
        expect [Pair(_id_token_name, 1)] = dict.to_pairs(continuing_id)

        expect and{
          rational.compare(s, rational.zero) != Less,
          rational.compare(s, rational.from_int(1)) != Greater,
          output.address.payment_credential == account_script,
        }

        ((num, denom), Some(utxo_intent_datum), continuing_id)
      }
      None -> ((1, 1), None, dict.empty)
    }
    let complement = (satisfaction.2nd - satisfaction.1st, satisfaction.2nd)

    let (burn_update, account_data_update) = when redeemer.redeemer is {
      NoncedIntent{intent: signed_intent} -> {
        expect valid_intent(signed_intent, input)
        let Intent{fee, partial, payload, account: intent_account, ..} = signed_intent.intent

        expect and {
          intent_account == account_id,
          fee >= 0
        }

        (dict.empty, when payload is {
          SendIntent{recipient, assets} -> {
            let value = assets.from_asset_list(assets)

            dict.from_pairs([
              Pair(
                recipient,
                OwnerAccumulator {
                  input: None,
                  output: None,
                  gain: value,
                  loss: assets.zero,
                }
              ),
              Pair(
                account_id,
                OwnerAccumulator {
                  input: None,
                  output: None,
                  gain: assets.zero,
                  loss: assets.add(value, "", "", fee),
                }
              )
            ])
          }
          ExchangeIntent{offer, demand} -> {
            if satisfaction.1st != satisfaction.2nd {
              let satisfied_demand = assets.from_asset_list(scale(demand, satisfaction))
              let satisfied_offer = assets.from_asset_list(scale(offer, satisfaction))
              let remaining_demand = scale(demand, complement)
              let remaining_offer = scale(offer, complement)
            
              let expected_continuing_datum = UtxoIntent {
                account: account_id,
                fee,
                exchange: ExchangeIntent {
                  offer: remaining_offer,
                  demand: remaining_demand
                },
                partial
              }

              expect and {
                continuing_datum == Some(expected_continuing_datum),
                or {
                  partial,
                  satisfaction.1st == 0
                }
              }

              dict.from_ascending_pairs([Pair(
                account_id,
                OwnerAccumulator {
                  input: None,
                  output: None,
                  gain: satisfied_demand,
                  loss: assets.add(satisfied_offer, "", "", fee),
                }
              )])
            } else {
              dict.from_ascending_pairs([Pair(
                account_id,
                OwnerAccumulator {
                  input: None,
                  output: None,
                  gain: assets.from_asset_list(demand),
                  loss: assets.add(assets.from_asset_list(offer), "", "", fee),
                }
              )])
            }
          }
        })
      }
      SpentIntent{input_index} -> {
        expect Some(intent_input) = list.at(inputs, input_index)
        expect UtxoIntent{exchange, account, fee, partial}: AccountDatum = {
          expect InlineDatum(datum) = intent_input.output.datum
          datum
        }
        expect ExchangeIntent{offer, demand} = exchange
        let intent_id = assets.tokens(intent_input.output.value, account_script_hash)
        expect [Pair(_id_token_name, 1)] = dict.to_pairs(intent_id)
        let burn = dict.map(intent_id, fn (_key, value) { -value })

        let update = if satisfaction.1st != satisfaction.2nd {
          let satisfied_demand = assets.from_asset_list(scale(demand, satisfaction))
          let satisfied_offer = assets.from_asset_list(scale(offer, satisfaction))
          let remaining_demand = scale(demand, complement)
          let remaining_offer = scale(offer, complement)

          let expected_continuing_datum = UtxoIntent {
            account,
            fee,
            partial,
            exchange: ExchangeIntent {
              offer: remaining_offer,
              demand: remaining_demand
            },
          }

          expect and {
            continuing_datum == Some(expected_continuing_datum),
            partial
          }

          dict.from_ascending_pairs([Pair(
            account_id,
            OwnerAccumulator {
              input: None,
              output: None,
              gain: satisfied_demand,
              loss: assets.add(satisfied_offer, "", "", fee),
            }
          )])
        } else {
          dict.from_ascending_pairs([Pair(
            account_id,
            OwnerAccumulator {
              input: None,
              output: None,
              gain: assets.from_asset_list(demand),
              loss: assets.add(assets.from_asset_list(offer), "", "", fee),
            }
          )])
        }

        (burn, update)
      }
    }
    return(
      (
        dict.union(acc.1st, dict.union(continuing_id, burn_update)),
        merge(acc.2nd, account_data_update)
      ),
      if satisfaction.1st == satisfaction.2nd {
        continuing_outputs
      } else {
        builtin.tail_list(continuing_outputs)
      }
    )
  }
}

fn validate_input(
  account_script: Credential,
  inputs: List<Input>
) {
  expect Script(account_script_hash) = account_script
  fn (
    input: Input,
    (remaining_spends, remaining_outputs) as remaining: (List<AccountSpend>, List<Output>),
    acc: (Dict<AssetName, Int>, Dict<AssetName, OwnerAccumulator>),
    return
  ) {
    if input.output.address.payment_credential == account_script {
      expect InlineDatum(datum) = input.output.datum
      if datum is Account{id: account_id, nonce: datum_nonce, pub_key_hash, verification_key}: AccountDatum {
        expect [account_output, ..continuing_outputs] = list.drop_while(
          remaining_outputs,
          fn (output) {
            output.address.payment_credential != account_script
          }
        )
    
        expect Account{
          id: out_id,
          pub_key_hash: out_pkh,
          verification_key: out_vkey,
          nonce: out_nonce,
        }: AccountDatum = {
          expect InlineDatum(datum) = account_output.datum
          datum
        }
    
        let id_tokens = assets.tokens(account_output.value, account_script_hash)
        expect and{
          id_tokens == assets.tokens(input.output.value, account_script_hash),
          dict.to_pairs(id_tokens) == [Pair(out_id, 1)],
          out_pkh == pub_key_hash,
          out_vkey == verification_key,
          out_id == account_id,
        }
    
        when remaining_spends is {
          [spend, ..new_remaining_spends] -> {
            let AccountSpend{account, intents} = spend
            expect account == account_id
    
            let max_nonce = list.foldl(intents, datum_nonce - 1, fn(intent, prev) {
              when intent.redeemer is {
                NoncedIntent{intent} -> {
                  expect intent.intent.nonce > prev
                  intent.intent.nonce
                }
                _ -> prev
              }
            })
    
            expect out_nonce > max_nonce
    
            let (mint_updates, account_data_updates), new_remaining_outputs <- list.foldl2(
              intents,
              (
                dict.empty,
                dict.from_ascending_pairs([Pair(
                  account_id,
                  OwnerAccumulator {
                    input: Some(input),
                    output: Some(account_output),
                    gain: assets.zero,
                    loss: assets.zero,
                  }
                )])
              ),
              continuing_outputs,
              validate_intent(account_script, input, account_id, inputs)
            )
            return(
              (new_remaining_spends, new_remaining_outputs),
              (dict.union(acc.1st, mint_updates), merge(acc.2nd, account_data_updates))
            )
          }
          _ -> return(remaining, acc)
        }
      } else {
        return(remaining, acc)
      }
    } else {
      return(remaining, acc)
    }
  }
}

fn validate_spends(
  spends: List<AccountSpend>,
  account_script: Credential,
  inputs: List<Input>,
  outputs: List<Output>,
  mint: Value,
) -> Bool {
  expect Script(account_script_hash) = account_script
  expect ([], _), result <- list.foldl2(
    inputs,
    (spends, outputs),
    (dict.empty, dict.empty),
    validate_input(account_script, inputs),
  )

  let account_data_valid = list.foldl(
    dict.to_pairs(result.2nd),
    True,
    fn (account_data, acc) {
      let Pair(_account_id, OwnerAccumulator{input, output, gain, loss}) = account_data
      expect Some(output) = output
      expect Some(input) = input
      let delta = assets.merge(output.value, assets.negate(input.output.value))
      let correct_loss = assets.reduce(delta, True, fn (policy_id, asset_name, token_delta, acc) {
        acc && or{
          token_delta >= 0,
          -token_delta <= assets.quantity_of(loss, policy_id, asset_name)
        }
      })

      let correct_gain = assets.reduce(gain, True, fn (policy_id, asset_name, expected_gain, acc) {
        acc && assets.quantity_of(delta, policy_id, asset_name) >= expected_gain
      })

      and {
        acc,
        correct_loss,
        correct_gain,
      }
    }
  )

  and{
    assets.tokens(mint, account_script_hash) == result.1st,
    account_data_valid,
  }
}

validator account(sequencer: KeyHash, sync_fee: Int) {
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
          sync_fee,
          account,
          self.inputs,
          self.outputs,
          self.mint
        ) 
      SpendAccounts(spends) -> {
        validate_account_spends(
          spends,
          account,
          self.inputs,
          self.outputs,
          self.mint
        )
      }
    }
  }

  publish(_redeemer: Data, _certificate: Data, _self: Data) -> Bool {
    True
  }
}
