use aiken/cbor
use aiken/collection/dict
use aiken/collection/list
use aiken/collection/pairs
use aiken/option
use cardano/transaction.{InlineDatum, Input, Output, ScriptPurpose, Withdraw, find_script_outputs}
use cardano/address.{Address, Script}
use cardano/assets.{Value, AssetName, PolicyId, ada_policy_id}
use cardano/assets/strategy.{DiscardResult, KeepResult}

use account/types.{
  Account,
  AccountDatum,
  AccountRedeemer,
  AccountSpend,
  ExchangeIntent,
  NoncedIntent,
  ScriptHash,
  SpendAccounts,
  SpendRedeemer,
  SpentIntent,
  UtxoIntent,
  AssetList,
  IntentPayload,
} as account_types

use distribution/merkle.{remove_leaf, verify_leaf}
use distribution/types.{
  Claim,
  DistributionDatum,
  MerkleStep,
  MintDistributionRedeemer,
}
use distribution/utils.{and_}

fn find_reward_token(own_policy_id: PolicyId) {
  fn(
    policy_id: PolicyId,
    asset_name: AssetName,
    amount: Int,
    keep: KeepResult<(PolicyId, AssetName, Int)>,
    discard: DiscardResult<(PolicyId, AssetName, Int)>
  ) -> List<(PolicyId, AssetName, Int)> {
    if policy_id != ada_policy_id && policy_id != own_policy_id {
      keep((policy_id, asset_name, amount))
    } else {
      discard()
    }
  }
}

fn verify_claim(output: Output, claim: Claim) -> Bool {
  let (reward, _spend_index, path) = claim
  expect Output { address, value: output_value, datum: InlineDatum(datum), .. } = output
  expect DistributionDatum { id: distribution_id, root_hash, depth }: DistributionDatum = datum
  expect Script(own_policy_id) = address.payment_credential

  // implicitly asserts that the only three assets are ADA, our STT, and the
  // reward token
  expect [(_, _, reward_amount)] =
    assets.flatten_with(output_value, find_reward_token(own_policy_id))

  let has_expected_amount = if (list.length(path) > 0) {
    expect Some(MerkleStep { amount: expected_amount, .. }) = list.last(path)
    reward_amount == expected_amount
  } else {
    True
  }

  and_(
    [
      (dict.to_pairs(assets.tokens(output_value, own_policy_id)) == [Pair(distribution_id, 1)])?,
      (list.length(path) == depth)?,
      has_expected_amount?,
      //(reward_amount == expected_amount)?, // why is this here and commented out?
      (verify_leaf(reward, root_hash, path))?,
    ],
  )
}

pub fn validate_mint(
  redeemers: List<MintDistributionRedeemer>,
  outputs: List<Output>,
  mint: Value,
  own_policy_id: PolicyId,
) -> Bool {
  let own_outputs = find_script_outputs(outputs, own_policy_id)
  let minted_tokens =
    mint
      |> assets.tokens(own_policy_id)
  let minted_ids = dict.keys(minted_tokens)
  let minted_amounts = dict.values(minted_tokens)
  let expected_ids = list.map(redeemers, fn(x) { x.id })

  let valid_distributions =
    list.map2(
      own_outputs,
      list.map(redeemers, fn(x) { x.sample }),
      verify_claim,
    )

  and_(
    [
      and_(valid_distributions)?,
      (list.length(own_outputs) == list.length(redeemers))?,
      (minted_ids == expected_ids)?,
      list.all(minted_amounts, fn(x) { x == 1 })?,
    ],
  )
}

pub fn validate_cancel(
  distributor: Address,
  datum: DistributionDatum,
  own_input: Output,
  outputs: List<Output>
) -> Bool {
  expect Script(own_policy_id) = own_input.address.payment_credential

  // allow if the token is missing always, the datum might be bad
  // otherwise only allow if all tokens go to distributor
  or{
    (assets.quantity_of(own_input.value, own_policy_id, datum.id) == 0)?,
    list.any(outputs, fn (output) {
      output.address == distributor && output.value == own_input.value
    })
  }
}

pub fn validate_claim(
  datum: DistributionDatum,
  claim: Claim,
  own_input: Output,
  account_script: ScriptHash,
  inputs: List<Input>,
  outputs: List<Output>,
  mint: Value,
  redeemers: Pairs<ScriptPurpose, Data>
) -> Bool {
  expect Script(own_policy_id) = own_input.address.payment_credential
  let (reward, spend_index, path) = claim
  when
    assets.flatten_with(own_input.value, find_reward_token(own_policy_id))
  is {
    [] ->
      (assets.quantity_of(mint, own_policy_id, datum.id) == -1)?
    [(reward_policy_id, reward_asset_name, _amount)] -> {
      let new_root_hash = remove_leaf(path, reward.amount)
      let expected_datum =
        DistributionDatum(datum.id, new_root_hash, datum.depth)
      let expected_output =
        Output(
          own_input.address,
          assets.add(
            own_input.value,
            reward_policy_id,
            reward_asset_name,
            -reward.amount,
          ),
          InlineDatum(expected_datum),
          own_input.reference_script,
        )

      expect SpendAccounts(spends): AccountRedeemer = {
        expect Some(redeemer) = pairs.get_first(redeemers, Withdraw(Script(account_script)))
        redeemer
      }

      expect Some(spend) = list.at(spends, spend_index)
      let spend_included = list.any(outputs, fn (output) { 
        if (output.address.payment_credential == Script(account_script)) {
          expect InlineDatum(datum) = output.datum
          if datum is Account{..}: AccountDatum {
            expect Account{id, pub_key_hash, ..} = datum
            and{
              id == spend.account,
              pub_key_hash == reward.recipient,
            }
          } else {
            False
          }
        } else {
          False
        }
      })
      trace cbor.diagnostic(spend.intents)
      expect [claim_assets] = list.filter_map(spend.intents, parse_claim_assets(inputs, _))

      let intent_correct = claim_assets == [Pair(reward_policy_id, [Pair(reward_asset_name, reward.amount)])]

      and{
        verify_claim(own_input, claim),
        list.has(outputs, expected_output)?,
        spend_included?,
        intent_correct?,
      }
    }
    _ -> False
  }
}

fn parse_claim_assets(inputs: List<Input>, spendRedeemer: SpendRedeemer) -> Option<AssetList> {
  let SpendRedeemer{redeemer, satisfaction} = spendRedeemer
  when satisfaction is {
    None -> {
      when redeemer is {
        NoncedIntent{intent} -> {
          intent_payload_to_claim_assets(intent.intent.payload)
        }
        SpentIntent{output_reference} -> {
          inputs
            |> list.find(fn (input) { input.output_reference == output_reference })
            |> option.and_then(fn (input) {
              expect InlineDatum(datum) = input.output.datum
              if datum is UtxoIntent{exchange, ..}: AccountDatum {
                intent_payload_to_claim_assets(exchange)
              } else {
                None
              }
            })
        }
      }
    }
    Some(_) -> None
  }
}

fn intent_payload_to_claim_assets(payload: IntentPayload) -> Option<AssetList> {
  when payload is {
    ExchangeIntent{offer, demand} -> when offer is {
      [] -> Some(demand)
      _ -> None
    }
    _ -> None
  }
}
