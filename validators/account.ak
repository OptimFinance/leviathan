use aiken/collection/list
use aiken/collection/pairs
use aiken/collection/dict.{Dict}
use aiken/crypto.{blake2b_224}
use aiken/math/rational
use aiken/math.{min}
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
  Credential,
  Script,
  VerificationKey,
}
use cardano/assets.{AssetName, PolicyId, Value}
use account/types.{
  AccountDatum,
  AccountRedeemer,
  AssetList,
  ExchangeIntent,
  IdMintRedeemer,
  InboxDatum,
  Intent,
  KeyHash,
  NoncedIntent,
  ScriptHash,
  AccountSpend,
  SendIntent,
  SpentIntent,
  SyncAccounts,
  SpendAccounts,
  UtxoIntent,
}
use account/utils.{
  get_output_datum,
  mint_own_id
}

use intent.{valid_intent}

type OwnerAccumulator {
  input: Option<Input>,
  gain: Value,
  loss: Value,
  nonce: Int,
}

fn list_sync(
  account_script: Credential,
  inbox_script: Credential,
  inputs: List<Input>,
  outputs: List<Output>,
) -> Bool {
  let get_owner = fn(output: Output) {
    let credential = output.address.payment_credential
    
    if credential == account_script {
      expect datum: AccountDatum = {
        expect InlineDatum(datum) = output.datum
        datum
      }
      Some(datum.pub_key_hash)
    } else if credential == inbox_script {
      expect datum: KeyHash = {
        expect InlineDatum(datum) = output.datum
        datum
      }
      Some(datum)
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
  inbox_script: Credential,
  inputs: List<Input>,
  outputs: List<Output>,
) -> Bool {
  list_sync(account_script, inbox_script, inputs, outputs)
}

fn merge(a: Dict<AssetName, OwnerAccumulator>, b: Dict<AssetName, OwnerAccumulator>) {
  dict.union_with(a, b, fn (_key, a, b, keep, _discard) {
    keep(OwnerAccumulator {
      input: option.choice([b.input, a.input]),
      gain: assets.merge(a.gain, b.gain),
      loss: assets.merge(a.loss, b.loss),
      nonce: min(a.nonce, b.nonce)
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
  utxo_intent_script: ScriptHash,
  inputs: List<Input>,
  outputs: List<Output>,
) -> Bool {
  expect [], account_data <- list.foldl2(
    inputs,
    spends,
    dict.empty,
    fn (input, remaining_spends, acc, return) {
      if input.output.address.payment_credential == account_script {
        expect datum: AccountDatum = {
          expect InlineDatum(datum) = input.output.datum
          datum
        }
        let account_id = datum.id
        when remaining_spends is {
          [spend, ..remaining] -> {
            let AccountSpend{account, intents} = spend
            let updates = list.foldl(
              intents,
              dict.empty,
              fn (redeemer, acc) {
                let (satisfaction, continuing_datum) = when redeemer.2nd is {
                  Some(((num, denom), output_index)) -> {
                    expect Some(s) = rational.new(num, denom)
                    expect rational.compare(s, rational.zero) != Less
                    expect rational.compare(s, rational.from_int(1)) != Greater
                    expect Some(output) = list.at(outputs, output_index)
                    expect utxo_intent_datum: UtxoIntent = {
                      expect InlineDatum(datum) = output.datum
                      datum
                    }
                    expect and{
                      output.address.payment_credential == Script(utxo_intent_script),
                      assets.has_any_nft(output.value, utxo_intent_script)
                    }

                    ((num, denom), Some(utxo_intent_datum))
                  }
                  None -> ((1, 1), None)
                }
                let complement = (satisfaction.2nd - satisfaction.1st, satisfaction.2nd)
                let update = when redeemer.1st is {
                  NoncedIntent{intent: signed_intent} -> {
                    expect valid_intent(signed_intent, input)
                    let Intent{fee, nonce, partial, payload, account: intent_account} = signed_intent.intent
                    expect intent_account == account
                    expect nonce >= datum.nonce
                    when payload is {
                      SendIntent{recipient, assets} -> {
                        expect satisfaction.1st == satisfaction.2nd
                        let value = assets.from_asset_list(scale(assets, satisfaction))
                        dict.from_pairs([
                          Pair(
                            recipient,
                            OwnerAccumulator {
                              input: None,
                              gain: value,
                              loss: assets.zero,
                              nonce: 0
                            }
                          ),
                          Pair(
                            account_id,
                            OwnerAccumulator {
                              input: Some(input),
                              gain: assets.zero,
                              loss: assets.add(value, "", "", -fee),
                              nonce,
                            }
                          )
                        ])
                      }
                      ExchangeIntent{offer, demand} -> {
                        expect or{
                          partial,
                          satisfaction.1st == satisfaction.2nd
                        }
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
                        expect continuing_datum == Some(expected_continuing_datum)

                        dict.from_ascending_pairs([Pair(
                          account_id,
                          OwnerAccumulator {
                            input: Some(input),
                            gain: satisfied_demand,
                            loss: assets.add(satisfied_offer, "", "", fee),
                            nonce
                          }
                        )])
                      }
                    }
                  }
                  SpentIntent{input_index} -> {
                    expect Some(intent_input) = list.at(inputs, input_index)
                    expect intent_datum: UtxoIntent = {
                      expect InlineDatum(datum) = intent_input.output.datum
                      datum
                    }
                    expect or{
                      intent_datum.partial,
                      satisfaction.1st == satisfaction.2nd
                    }
                    expect ExchangeIntent{offer, demand} = intent_datum.exchange
                    let remaining_demand = scale(demand, complement)
                    let remaining_offer = scale(offer, complement)
                    let expected_continuing_datum = UtxoIntent {
                      ..intent_datum,
                      exchange: ExchangeIntent {
                        offer: remaining_offer,
                        demand: remaining_demand
                      },
                    }
                    expect continuing_datum == Some(expected_continuing_datum)

                    dict.from_ascending_pairs([Pair(
                      account_id,
                      OwnerAccumulator {
                        input: Some(input),
                        gain: assets.from_asset_list(scale(demand, satisfaction)),
                        loss: assets.add(assets.from_asset_list(scale(offer, satisfaction)), "", "", -intent_datum.fee),
                        nonce: 0
                      }
                    )])
                  }
                }
                merge(acc, update)
              }
            )
            return(remaining, merge(acc, updates))
          }
          _ -> return(remaining_spends, acc)
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
        expect datum: AccountDatum = {
          expect InlineDatum(datum) = output.datum
          datum
        }
        when remaining_account_data is {
          [account_data, ..new_account_data] -> {
            let Pair(account_id, OwnerAccumulator{input, gain, loss, nonce}) = account_data
            expect Some(input) = input
            let delta = assets.merge(output.value, assets.negate(input.output.value))

            let correct_loss = assets.reduce(delta, True, fn (policy_id, asset_name, quantity, acc) {
              acc && or{
                quantity > 0,
                -quantity <= assets.quantity_of(loss, policy_id, asset_name)
              }
            })

            let correct_gain = assets.reduce(gain, True, fn (policy_id, asset_name, quantity, acc) {
              acc && assets.quantity_of(delta, policy_id, asset_name) >= quantity
            })

            expect and {
              account_id == datum.id,
              datum.nonce > nonce,
              correct_loss,
              correct_gain,
            }
            new_account_data
          }
          _ -> []
        }
      } else {
        remaining_account_data
      }
    }
  )

  True
}

validator account(
  sequencer: KeyHash,
  inbox: ScriptHash,
  utxo_intent_script: ScriptHash
) {
  mint(redeemer: IdMintRedeemer, own_policy_id: PolicyId, self: Transaction) -> Bool {
    let valid_account_output = fn(output: Output, self: Transaction) {
      expect datum: AccountDatum = get_output_datum(output, self.datums)

      let valid_owner = and {
        blake2b_224(datum.verification_key) == datum.pub_key_hash,
        list.has(self.extra_signatories, datum.pub_key_hash)
      }

      and{
        valid_owner,
        datum.nonce == 0
      }
    }
    
    mint_own_id(redeemer, own_policy_id, self, valid_account_output)
  }

  spend(_datum: Option<Data>, _redeemer: Data, own_input_ref: OutputReference, self: Transaction) -> Bool {
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
          Script(inbox),
          account,
          self.inputs,
          self.outputs,
        ) 
      SpendAccounts(spends) ->
        validate_spends(
          spends,
          account,
          utxo_intent_script,
          self.inputs,
          self.outputs,
        )
    }
  }
}

validator inbox() {
  spend(_datum: Option<InboxDatum>, _redeemer: Data, _own_input_ref: OutputReference, _self: Transaction) -> Bool {
    True
  }
}
