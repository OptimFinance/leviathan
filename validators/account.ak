use aiken/builtin
use aiken/collection/list
use aiken/collection/pairs
use aiken/collection/dict.{Dict}
use aiken/crypto.{blake2b_224}
use aiken/math/rational
use aiken/math.{max}
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
  UtxoIntent,
  AccountRedeemer,
  AssetList,
  ExchangeIntent,
  IdMintRedeemer,
  Intent,
  IntentSatisfaction, KeyHash,
  NoncedIntent,
  AccountSpend,
  SendIntent,
  SpentIntent,
  SyncAccounts,
  SpendAccounts,
}
use account/utils.{
  mint_own_id
}

use intent.{valid_intent}

type OwnerAccumulator {
  input: Option<Input>,
  gain: Value,
  loss: Value,
  nonce: Int,
  num_continuing_outputs: Int,
}

pub fn list_sync(
  account_script: Credential,
  inputs: List<Input>,
  outputs: List<Output>,
) -> Bool {
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
        VerificationKey(pkh) -> Some(pkh)
        _ -> None
      }
    }
  }

  let in_value_map: Dict<ByteArray, Value> = list.foldl(
    inputs,
    dict.empty,
    fn (input, prev: Dict<ByteArray, Value>) {
      let owner = get_owner(input.output)
      when owner is {
        Some(pkh) ->
          when dict.get(prev, pkh) is {
            Some(prev_entry) -> dict.insert(prev, pkh, assets.merge(prev_entry, input.output.value))
            None -> dict.insert(prev, pkh, input.output.value)
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

  in_value_map == out_value_map
}

fn validate_syncs(
  account_script: Credential,
  inputs: List<Input>,
  outputs: List<Output>,
) -> Bool {
  list_sync(account_script, inputs, outputs)
}

fn merge(a: Dict<AssetName, OwnerAccumulator>, b: Dict<AssetName, OwnerAccumulator>) {
  dict.union_with(a, b, fn (_key, a, b, keep, _discard) {
    keep(OwnerAccumulator {
      input: option.choice([b.input, a.input]),
      gain: assets.merge(a.gain, b.gain),
      loss: assets.merge(a.loss, b.loss),
      nonce: max(a.nonce, b.nonce),
      num_continuing_outputs: a.num_continuing_outputs + b.num_continuing_outputs,
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

fn validate_spends(
  spends: List<AccountSpend>,
  account_script: Credential,
  inputs: List<Input>,
  outputs: List<Output>,
) -> Bool {
  expect Script(account_script_hash) = account_script
  expect [], account_data <- list.foldl2(
    inputs,
    spends,
    dict.empty,
    fn (input, remaining_spends, acc, return) {
      if input.output.address.payment_credential == account_script {
        expect InlineDatum(datum) = input.output.datum
        if datum is Account{id: datum_id, nonce: datum_nonce, ..}: AccountDatum {
          let account_id = datum_id
          when remaining_spends is {
            [spend, ..remaining] -> {
              let AccountSpend{account, intents, outputs_start} = spend
              expect account == account_id

              // check that all continuing outputs for this user are in sequence
              // beginning at `outputs_start`. when traversing the outputs we
              // ensure that the number of `UtxoIntent` outputs found for this
              // account matches the number of distinct outputs validated
              // beginning at this index
              let continuing_outputs = outputs_start
                |> option.map(list.drop(outputs, _)) 
                |> option.or_else([])

              let updates, _ <- list.foldl2(
                intents,
                dict.from_ascending_pairs([Pair(
                  account_id,
                  OwnerAccumulator {
                    input: Some(input),
                    gain: assets.zero,
                    loss: assets.zero,
                    nonce: datum_nonce,
                    num_continuing_outputs: 0,
                  }
                )]),
                continuing_outputs,
                fn (redeemer, acc, continuing_outputs, return) {
                  let (satisfaction, continuing_datum) = when redeemer.satisfaction is {
                    Some(IntentSatisfaction{ num, denom }) -> {
                      expect Some(s) = rational.new(num, denom)
                      expect Some(output) = list.head(continuing_outputs)
                      expect UtxoIntent{..} as utxo_intent_datum: AccountDatum = {
                        expect InlineDatum(datum) = output.datum
                        datum
                      }

                      expect and{
                        rational.compare(s, rational.zero) != Less,
                        rational.compare(s, rational.from_int(1)) != Greater,
                        output.address.payment_credential == account_script,
                        assets.has_any_nft(output.value, account_script_hash)
                      }

                      ((num, denom), Some(utxo_intent_datum))
                    }
                    None -> ((1, 1), None)
                  }
                  let num_continuing_outputs = if option.is_some(continuing_datum) { 1 } else { 0 }
                  let complement = (satisfaction.2nd - satisfaction.1st, satisfaction.2nd)
                  let update = when redeemer.redeemer is {
                    NoncedIntent{intent: signed_intent} -> {
                      expect valid_intent(signed_intent, input)
                      let Intent{fee, nonce, partial, payload, account: intent_account} = signed_intent.intent
                      expect intent_account == account
                      expect nonce >= datum_nonce
                      when payload is {
                        SendIntent{recipient, assets} -> {
                          expect num_continuing_outputs == 0
                          let value = assets.from_asset_list(assets)
                          dict.from_pairs([
                            Pair(
                              recipient,
                              OwnerAccumulator {
                                input: None,
                                gain: value,
                                loss: assets.zero,
                                nonce: 0,
                                num_continuing_outputs,
                              }
                            ),
                            Pair(
                              account_id,
                              OwnerAccumulator {
                                input: None,
                                gain: assets.zero,
                                loss: assets.add(value, "", "", fee),
                                nonce,
                                num_continuing_outputs,
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
                              account,
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
                                gain: satisfied_demand,
                                loss: assets.add(satisfied_offer, "", "", fee),
                                nonce,
                                num_continuing_outputs,
                              }
                            )])
                          } else {
                            dict.from_ascending_pairs([Pair(
                              account_id,
                              OwnerAccumulator {
                                input: None,
                                gain: assets.from_asset_list(demand),
                                loss: assets.add(assets.from_asset_list(offer), "", "", fee),
                                nonce,
                                num_continuing_outputs,
                              }
                            )])
                          }
                        }
                      }
                    }
                    SpentIntent{input_index} -> {
                      expect Some(intent_input) = list.at(inputs, input_index)
                      expect UtxoIntent{exchange, account, fee, partial}: AccountDatum = {
                        expect InlineDatum(datum) = intent_input.output.datum
                        datum
                      }
                      expect ExchangeIntent{offer, demand} = exchange

                      if satisfaction.1st != satisfaction.2nd {
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
                            gain: satisfied_demand,
                            loss: assets.add(satisfied_offer, "", "", fee),
                            nonce: 0,
                            num_continuing_outputs,
                          }
                        )])
                      } else {
                        dict.from_ascending_pairs([Pair(
                          account_id,
                          OwnerAccumulator {
                            input: None,
                            gain: assets.from_asset_list(demand),
                            loss: assets.add(assets.from_asset_list(offer), "", "", fee),
                            nonce: 0,
                            num_continuing_outputs,
                          }
                        )])
                      }
                    }
                  }
                  return(
                    merge(acc, update),
                    if num_continuing_outputs == 0 {
                      continuing_outputs
                    } else {
                      builtin.tail_list(continuing_outputs)
                    }
                  )
                }
              )
              return(remaining, merge(acc, updates))
            }
            _ -> return(remaining_spends, acc)
          }
        } else {
          return(remaining_spends, acc)
        }
      } else {
        return(remaining_spends, acc)
      }
    }
  )

  expect [] = list.foldl(
    outputs,
    dict.to_pairs(account_data),
    fn (output, remaining_account_data) {
      if output.address.payment_credential == account_script {
        expect InlineDatum(datum) = output.datum
        if datum is Account{id: datum_id, nonce: datum_nonce, ..}: AccountDatum {
          when remaining_account_data is {
            [account_data, ..new_account_data] -> {
              let Pair(account_id, OwnerAccumulator{input, gain, loss, nonce, num_continuing_outputs}) = account_data
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

              expect and {
                account_id == datum_id,
                datum_nonce > nonce,
                correct_loss,
                correct_gain,
                num_continuing_outputs == 0,
              }
              new_account_data
            }
            _ -> []
          }
        } else if datum is UtxoIntent{account, ..}: AccountDatum {
          // we want to check that the number of continuing outputs checked
          // matches the number we find in the outputs for immediate next user
          when remaining_account_data is {
            [Pair(owner, acc), ..rest] -> {
              expect owner == account
              list.push(
                rest,
                Pair(owner, OwnerAccumulator{..acc, num_continuing_outputs: acc.num_continuing_outputs - 1})
              )
            }
            _ -> []
          }
        } else {
          remaining_account_data
        }
      } else {
        remaining_account_data
      }
    }
  )

  True
}

validator account(sequencer: KeyHash) {
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
        UtxoIntent{..} -> {
          expect Some(withdraw_redeemer) = pairs.get_first(self.redeemers, Withdraw(Script(own_policy_id)))
          expect SpendAccounts(_spends) = withdraw_redeemer
          True
        }
        Inbox{..} -> True
      }
    }
    
    mint_own_id(redeemer, own_policy_id, self, valid_account_output)
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
        validate_syncs(
          account,
          self.inputs,
          self.outputs,
        ) 
      SpendAccounts(spends) ->
        validate_spends(
          spends,
          account,
          self.inputs,
          self.outputs,
        )
    }
  }
}
