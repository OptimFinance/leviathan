use account/intent.{validate_signed_intent}
use account/types.{
  Account, AccountData, AccountDatum, AccountOutput, AccountSpend, AssetList,
  ExchangeIntent, Inbox, Intent, IntentPayload, IntentSatisfaction, KeyHash,
  NoncedIntent, SendIntent, SpendRedeemer, SpentIntent, UtxoIntent
}
use aiken/collection/dict.{Dict}
use aiken/collection/list
use aiken/option
use cardano/address.{Credential, Script, VerificationKey}
use cardano/assets.{AssetName, PolicyId, Value}
use cardano/transaction.{InlineDatum, Input, Output}

pub type OwnerAccumulator {
  input: Option<AccountOutput>,
  output: Option<AccountOutput>,
  gain: Value,
  loss: Value,
}

pub type IntentData {
  account_asset_name: AssetName,
  mb_nonce: Option<Int>,
  fee: Int,
  payload: IntentPayload,
  partial: Bool,
}

pub type UtxoIntentOutput {
  policy_id: PolicyId,
  asset_name: AssetName,
  value: Value,
  data: IntentData,
}

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
      let value = input.output.value
      when owner is {
        Some(pkh) ->
          when dict.get(prev, pkh) is {
            Some(prev_entry) -> dict.insert(prev, pkh, assets.merge(prev_entry, value))
            None -> dict.insert(prev, pkh, assets.add(value, fee_policy_id, fee_asset_name, -sync_fee))
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
                  owner_value |> assets.add(account_script_hash, id, 1)
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


  zip_pred(
    dict.to_pairs(in_value_map),
    dict.to_pairs(out_value_map_with_burns),
    fn (Pair(owner_in, value_in), Pair(owner_out, value_out)) {
      owner_in == owner_out && zip_pred(
        dict.to_pairs(assets.to_dict(value_in)),
        dict.to_pairs(assets.to_dict(value_out)),
        fn (Pair(policy_id_in, tokens_in), Pair(policy_id_out, tokens_out)) {
          policy_id_in == policy_id_out && zip_pred(
            dict.to_pairs(tokens_in),
            dict.to_pairs(tokens_out),
            fn (Pair(asset_name_in, quantity_in), Pair(asset_name_out, quantity_out)) {
              asset_name_in == asset_name_out && quantity_out >= quantity_in
            }
          )
        }
      )
    }
  )
}

pub fn validate_account_spends(
  account_spends: List<AccountSpend>,
  account_script_cred: Credential,
  fee_policy_id: PolicyId,
  fee_asset_name: AssetName,
  inputs: List<Input>,
  outputs: List<Output>,
  mint: Value,
) -> Bool {
  expect Script(account_script_hash) = account_script_cred

  let ((owner_acc_dict, mint_dict), _) =
    list.foldl2(
      inputs,
      (dict.empty, dict.empty),
      (account_spends, outputs),
      fn(
        input,
        (prev_owner_acc_dict, prev_mint_dict) as acc,
        (account_spends, outputs) as rests,
        return,
      ) {
        let mb_account = input_to_account(account_script_cred, account_script_hash, input)

        when mb_account is {
          Some(input_account) -> {
            expect [account_spend, ..rest_account_spends] = account_spends

            expect (Some(output_account), rest_outputs) =
              drop_maybe(
                outputs,
                output_to_account(account_script_cred, account_script_hash, _),
              )

            expect
              validate_account_in_out_spend(
                input_account,
                output_account,
                account_spend,
              )?

            let ((owner_acc_dict, mint_dict), rest_outputs) =
              validate_account_intents(
                account_script_hash,
                fee_policy_id,
                fee_asset_name,
                input_account,
                output_account,
                account_spend.intents,
                inputs,
                rest_outputs,
              )

            return(
              (
                merge_owner_accs(prev_owner_acc_dict, owner_acc_dict),
                dict.union(prev_mint_dict, mint_dict),
              ),
              (rest_account_spends, rest_outputs),
            )
          }
          _ -> return(acc, rests)
        }
      },
      fn(account_spends, outputs) { (account_spends, outputs) },
    )

  let owner_accs = dict.values(owner_acc_dict)

  let owner_accs_valid =
    list.all(
      owner_accs,
      fn(owner_acc) {
        let OwnerAccumulator { input, output, gain, loss } = owner_acc
        expect Some(output) = output
        expect Some(input) = input

        let delta = assets.merge(output.value, assets.negate(input.value))

        let correct_loss =
          assets.reduce(
            delta,
            True,
            fn(policy_id, asset_name, token_delta, acc) {
              acc && or {
                token_delta >= 0,
                -token_delta <= assets.quantity_of(loss, policy_id, asset_name),
              }
            },
          )

        let correct_gain =
          assets.reduce(
            gain,
            True,
            fn(policy_id, asset_name, expected_gain, acc) {
              acc && or {
                expected_gain <= 0,
                assets.quantity_of(delta, policy_id, asset_name) >= expected_gain
              }
            },
          )

        and {
          correct_loss?,
          correct_gain?,
        }
      },
    )

  and {
    (list.length(owner_accs) > 0)?,
    owner_accs_valid?,
    (assets.tokens(mint, account_script_hash) == mint_dict)?,
  }
}

fn validate_account_in_out_spend(
  input_account: AccountOutput,
  output_account: AccountOutput,
  account_spend: AccountSpend,
) -> Bool {
  and {
    (input_account.policy_id == output_account.policy_id)?,
    (input_account.asset_name == output_account.asset_name)?,
    (input_account.data.v_key == output_account.data.v_key)?,
    (input_account.data.pub_key_hash == output_account.data.pub_key_hash)?,
    (input_account.asset_name == account_spend.account)?,
  }
}

fn validate_account_intents(
  account_policy_id: PolicyId,
  fee_policy_id: PolicyId,
  fee_asset_name: AssetName,
  input_account: AccountOutput,
  output_account: AccountOutput,
  spend_redeemers: List<SpendRedeemer>,
  inputs: List<Input>,
  outputs: List<Output>,
) -> ((Dict<AssetName, OwnerAccumulator>, Dict<AssetName, Int>), List<Output>) {
  let ((a, b, max_nonce), rests) =
    list.foldl2(
      spend_redeemers,
      (
        dict.from_ascending_pairs(
          [
            Pair(
              input_account.asset_name,
              OwnerAccumulator {
                input: Some(input_account),
                output: Some(output_account),
                gain: assets.zero,
                loss: assets.zero,
              },
            ),
          ],
        ),
        dict.empty,
        input_account.data.nonce - 1,
      ),
      outputs,
      fn(
        spend_redeemer,
        (prev_owner_acc_dict, prev_mint_dict, prev_nonce),
        outputs,
        return,
      ) {
        let SpendRedeemer {
          redeemer: intent_redeemer,
          satisfaction: mb_satisfaction,
        } = spend_redeemer

        let (intent_data, mb_input_utxo_intent, max_nonce) =
          when intent_redeemer is {
            NoncedIntent { intent: signed_intent } -> {
              expect validate_signed_intent(signed_intent, input_account)

              let Intent { account, nonce, fee, payload, partial } = signed_intent.intent

              let intent_data =
                IntentData {
                  account_asset_name: account,
                  mb_nonce: Some(nonce),
                  fee,
                  payload,
                  partial,
                }

              expect nonce > prev_nonce

              (intent_data, None, nonce)
            }

            SpentIntent { output_reference } -> {
              expect Some(input) = list.find(inputs, fn (input) { input.output_reference == output_reference })

              expect Some(input_utxo_intent) = output_to_utxo_intent(account_policy_id, input.output)

              (input_utxo_intent.data, Some(input_utxo_intent), prev_nonce)
            }
          }

        let (owner_acc_dict, mint_dict, rest_outputs) =
          validate_intent(
            account_policy_id,
            input_account.asset_name,
            fee_policy_id,
            fee_asset_name,
            intent_data,
            mb_input_utxo_intent,
            mb_satisfaction,
            outputs,
          )

        return(
          (
            merge_owner_accs(prev_owner_acc_dict, owner_acc_dict),
            dict.union(prev_mint_dict, mint_dict),
            max_nonce,
          ),
          rest_outputs,
        )
      },
      fn(a, b) { (a, b) },
    )

  expect output_account.data.nonce == max_nonce + 1

  ((a, b), rests)
}

fn input_to_account(
  account_script_cred: Credential,
  account_policy_id: PolicyId,
  input: Input,
) -> Option<AccountOutput> {
  output_to_account(account_script_cred, account_policy_id, input.output)
}

pub fn output_to_account(
  account_script_cred: Credential,
  account_policy_id: PolicyId,
  output: Output,
) -> Option<AccountOutput> {
  if output.address.payment_credential == account_script_cred {
    when output.datum is {
      InlineDatum(datum) ->
        if datum
        is Account { id, verification_key, pub_key_hash, nonce }: AccountDatum {
          let data =
            AccountData { v_key: verification_key, pub_key_hash, nonce }
          let value = output.value
          if assets.quantity_of(value, account_policy_id, id) == 1 {
            Some(
              AccountOutput {
                policy_id: account_policy_id,
                asset_name: id,
                value,
                data,
              },
            )
          } else {
            None
          }
        } else {
          None
        }
      _ -> None
    }
  } else {
    None
  }
}

pub fn input_to_utxo_intent(
  account_policy_id: PolicyId,
  input: Input,
) -> Option<UtxoIntentOutput> {
  output_to_utxo_intent(account_policy_id, input.output)
}

pub fn output_to_utxo_intent(
  account_policy_id: PolicyId,
  output: Output,
) -> Option<UtxoIntentOutput> {
  if output.address.payment_credential == Script(account_policy_id) {
    when output.datum is {
      InlineDatum(datum) ->
        if datum
        is UtxoIntent { id: account_asset_name, fee, exchange, partial }: AccountDatum {
          let data =
            IntentData {
              account_asset_name,
              mb_nonce: None,
              fee,
              payload: exchange,
              partial,
            }
          let value = output.value
          when dict.to_pairs(assets.tokens(value, account_policy_id)) is {
            [Pair(utxo_intent_asset_name, 1)] ->
              Some(
                UtxoIntentOutput {
                  policy_id: account_policy_id,
                  asset_name: utxo_intent_asset_name,
                  value,
                  data,
                },
              )
            _ -> None
          }
        } else {
          None
        }
      _ -> None
    }
  } else {
    None
  }
}

fn validate_intent(
  account_policy_id: PolicyId,
  account_asset_name: AssetName,
  fee_policy_id: PolicyId,
  fee_asset_name: AssetName,
  intent_data: IntentData,
  mb_input_utxo_intent: Option<UtxoIntentOutput>,
  mb_satisfaction: Option<IntentSatisfaction>,
  outputs: List<Output>,
) -> (Dict<AssetName, OwnerAccumulator>, Dict<AssetName, Int>, List<Output>) {
  let IntentData {
    account_asset_name: intent_account_asset_name,
    fee,
    payload,
    partial,
    ..
  } = intent_data

  expect and {
      (fee >= 0)?,
      (account_asset_name == intent_account_asset_name)?,
    }

  // If the satisfaction is 0 there must not be an input UtxoIntent, there must
  // be a output UtxoIntent containing the full corresponding intent, but we
  // don't want to change the Account at all.
  when mb_satisfaction is {
    Some(IntentSatisfaction { num: 0, .. }) -> {
      expect None = mb_input_utxo_intent

      expect (Some(output_utxo_intent), rest_outputs) =
        drop_maybe(outputs, output_to_utxo_intent(account_policy_id, _))

      expect and {
          (output_utxo_intent.data.fee == fee)?,
          (output_utxo_intent.data.payload == payload)?,
          (output_utxo_intent.data.partial == partial)?,
          option.is_none(output_utxo_intent.data.mb_nonce)?
        }

      let owner_acc_dict = dict.from_pairs(
        [
          Pair(
            intent_account_asset_name,
            OwnerAccumulator {
              input: None,
              output: None,
              gain: assets.from_asset(fee_policy_id, fee_asset_name, -fee),
              loss: assets.from_asset(fee_policy_id, fee_asset_name, fee)
            }
          )
        ]
      )

      let mint_dict = dict.from_ascending_pairs(
        [Pair(output_utxo_intent.asset_name, 1)],
      )

      (owner_acc_dict, mint_dict, rest_outputs)
    }
    _ ->
      when payload is {
        SendIntent { recipient, assets } -> {
          expect None = mb_satisfaction

          let value = assets.from_asset_list(assets)
          let owner_acc_dict =
            dict.from_pairs(
              [
                Pair(
                  recipient,
                  OwnerAccumulator {
                    input: None,
                    output: None,
                    gain: value,
                    loss: assets.zero,
                  },
                ),
                Pair(
                  account_asset_name,
                  OwnerAccumulator {
                    input: None,
                    output: None,
                    gain: assets.zero,
                    loss: assets.add(value, fee_policy_id, fee_asset_name, fee),
                  },
                ),
              ],
            )
          (owner_acc_dict, dict.empty, outputs)
        }
        ExchangeIntent { offer, demand } -> {
          let (num, denom) as satisfaction_tuple =
            when mb_satisfaction is {
              Some(IntentSatisfaction { num, denom }) -> {
                expect and {
                    (num >= 0)?,
                    (num <= denom)?,
                    (denom > 0)?,
                    partial?,
                  }

                (num, denom)
              }
              None -> (1, 1)
            }

          let complement = (denom - num, denom)
          if num != denom {
            let satisfied_demand = assets.from_asset_list(scale(demand, satisfaction_tuple))
            let satisfied_offer = assets.from_asset_list(scale(offer, satisfaction_tuple))
            let remaining_demand = scale(demand, complement)
            let remaining_offer = scale(offer, complement)

            expect (Some(output_utxo_intent), rest_outputs) =
              drop_maybe(outputs, output_to_utxo_intent(account_policy_id, _))

            let (is_output_intent_nft_valid, utxo_intent_mint_dict) =
              mb_input_utxo_intent
                |> option.map(
                    fn(input_utxo_intent) {
                      (
                        input_utxo_intent.asset_name == output_utxo_intent.asset_name,
                        dict.empty,
                      )
                    },
                  )
                |> option.or_else(
                    (
                      True,
                      dict.from_ascending_pairs([Pair(output_utxo_intent.asset_name, 1)]),
                    ),
                  )

            expect and {
              is_output_intent_nft_valid,
              output_utxo_intent.data.fee == fee,
              output_utxo_intent.data.payload == ExchangeIntent {
                offer: remaining_offer,
                demand: remaining_demand,
              },
              output_utxo_intent.data.partial == partial,
            }

            let owner_acc_dict =
              dict.from_ascending_pairs(
                [
                  Pair(
                    account_asset_name,
                    OwnerAccumulator {
                      input: None,
                      output: None,
                      gain: assets.add(satisfied_demand, fee_policy_id, fee_asset_name, -fee),
                      loss: assets.add(satisfied_offer, fee_policy_id, fee_asset_name, fee),
                    },
                  ),
                ],
              )
            (owner_acc_dict, utxo_intent_mint_dict, rest_outputs)
          } else {
            let owner_acc_dict =
              dict.from_ascending_pairs(
                [
                  Pair(
                    account_asset_name,
                    OwnerAccumulator {
                      input: None,
                      output: None,
                      gain: assets.add(assets.from_asset_list(demand), fee_policy_id, fee_asset_name, -fee),
                      loss: assets.add(assets.from_asset_list(offer), fee_policy_id, fee_asset_name, fee),
                    },
                  ),
                ],
              )

            let utxo_intent_mint_dict =
              mb_input_utxo_intent
                |> option.map(
                    fn(input_utxo_intent) {
                      dict.from_ascending_pairs(
                        [Pair(input_utxo_intent.asset_name, -1)],
                      )
                    },
                  )
                |> option.or_else(dict.empty)

            (owner_acc_dict, utxo_intent_mint_dict, outputs)
          }
        }
      }
  }
}

fn drop_maybe(xs: List<a>, f: fn(a) -> Option<b>) -> (Option<b>, List<a>) {
  when xs is {
    [] -> (None, [])
    [x, ..rest] ->
      when f(x) is {
        Some(y) -> (Some(y), rest)
        None -> drop_maybe(rest, f)
      }
  }
}

pub fn merge_owner_accs(
  a: Dict<AssetName, OwnerAccumulator>,
  b: Dict<AssetName, OwnerAccumulator>,
) {
  dict.union_with(
    a,
    b,
    fn(_key, a, b, keep, _discard) {
      keep(
        OwnerAccumulator {
          input: option.choice([b.input, a.input]),
          output: option.choice([b.output, a.output]),
          gain: assets.merge(a.gain, b.gain),
          loss: assets.merge(a.loss, b.loss),
        },
      )
    },
  )
}

fn scale(assets: AssetList, (num, denom): (Int, Int)) {
  list.map(
    assets,
    fn(Pair(policy_id, tokens)) {
      Pair(
        policy_id,
        list.map(
          tokens,
          fn(Pair(token_name, quantity)) {
            Pair(token_name, quantity * num / denom)
          },
        ),
      )
    },
  )
}

fn zip_pred(xs: List<a>, ys: List<b>, pred: fn (a, b) -> Bool) -> Bool {
  when (xs, ys) is {
    ([x, ..xs], [y, ..ys]) -> pred(x, y) && zip_pred(xs, ys, pred)
    _ -> True
  }
}
