use aiken/collection/dict
use aiken/collection/list
use cardano/transaction.{InlineDatum, NoDatum, Output, Withdraw}
use cardano/address.{
  Address,
  Script,
  VerificationKey
}
use cardano/assets.{AssetName, PolicyId, Value}

use account/types.{
  Account,
  AccountSpend,
  ExchangeIntent,
  Intent,
  KeyHash,
  NoncedIntent,
  SignedIntent,
  SpendAccounts,
  SpendRedeemer
} as account_types

use distribution/merkle.{remove_leaf}
use distribution/types.{
  Claim,
  DistributionDatum,
  MintDistributionRedeemer,
  Proof,
  Reward,
}
use distribution/validation.{validate_cancel, validate_claim, validate_mint}
use distribution/quadtree.{
  QuadTree,
  QuadNode,
  QuadLeaf,
  QuadSelect,
  OnA,
  OnB,
  OnC,
  OnD
}
use distribution/rewardtree
use distribution/utils.{const_, id}

const distributor: KeyHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const own_policy_id: PolicyId = "bbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const reward_policy_id: PolicyId = "cccccccccccccccccccccccccccc"
const account_hash: KeyHash = "dddddddddddddddddddddddddddd"
const reward_asset_name: AssetName = ""

fn sample_tree_a() {
  QuadNode(
    QuadNode(
      QuadLeaf(Some(Reward("0000000000000000000000000000", 923875))),
      QuadLeaf(Some(Reward("1111111111111111111111111111", 17382507))),
      QuadLeaf(Some(Reward("2222222222222222222222222222", 2389752))),
      QuadLeaf(Some(Reward("3333333333333333333333333333", 902375))),
    ),
    QuadNode(
      QuadLeaf(Some(Reward("4444444444444444444444444444", 372895))),
      QuadLeaf(Some(Reward("5555555555555555555555555555", 2398756))),
      QuadLeaf(Some(Reward("6666666666666666666666666666", 937812))),
      QuadLeaf(Some(Reward("7777777777777777777777777777", 982375))),
    ),
    QuadLeaf(None),
    QuadLeaf(None)
  )
}

fn sample_tree_b() {
  QuadNode(
    QuadNode(
      QuadLeaf(Some(Reward("0000000000000000000000000000", 3289239))),
      QuadLeaf(Some(Reward("1111111111111111111111111111", 9167530))),
      QuadLeaf(Some(Reward("2222222222222222222222222222", 1798235))),
      QuadLeaf(Some(Reward("3333333333333333333333333333", 29357823))),
    ),
    QuadNode(
      QuadLeaf(Some(Reward("4444444444444444444444444444", 2189751))),
      QuadLeaf(Some(Reward("5555555555555555555555555555", 38975111))),
      QuadLeaf(Some(Reward("6666666666666666666666666666", 7128752))),
      QuadLeaf(Some(Reward("7777777777777777777777777777", 6219865))),
    ),
    QuadNode(
      QuadLeaf(Some(Reward("8888888888888888888888888888", 2367895))),
      QuadLeaf(Some(Reward("9999999999999999999999999999", 12348975))),
      QuadLeaf(None),
      QuadLeaf(None),
    ),
    QuadLeaf(None)
  )
}
 
fn script_address() { Address(Script(own_policy_id), None) }

type Distribution {
  datum: DistributionDatum,
  claim: Claim,
  amount: Int
}

fn get_distribution(
  distribution_id: ByteArray,
  tree: QuadTree<Reward>,
  selection: List<QuadSelect>
) -> Distribution {
  let extract_leaf =
    fn(claim: (QuadTree<Reward>, Proof)) {
      expect QuadLeaf{ value: Some(leafValue) } = claim.1st
      (leafValue, 0, claim.2nd)
    }
  let reward_amount = rewardtree.total_amount(tree)
  let root_hash = rewardtree.hash(tree)
  let depth = quadtree.depth(tree)
  let claim =
    list.foldl(
      selection,
      quadtree.init_path(tree),
      fn(x, a) { rewardtree.step_path(a, x) }
    ) |> extract_leaf
  Distribution(
    DistributionDatum(distribution_id, root_hash, depth),
    claim,
    reward_amount
  )
}

fn remove_policy(value: Value, policy_id: PolicyId) -> Value {
  list.foldl(
    dict.to_pairs(assets.tokens(value, policy_id)),
    value,
    fn(token, acc) {
      assets.add(acc, policy_id, token.1st, -token.2nd)
    }
  )
}

fn test_mint(
  transform_distributions: fn(List<Distribution>) -> List<Distribution>,
  transform_output_value: fn(Value) -> Value,
  transform_output_datum: fn(DistributionDatum) -> DistributionDatum,
  transform_mint_value: fn(Value) -> Value
) -> Bool {
  let distributor_address = Address(VerificationKey(distributor), None)
  let distributions =
    [ ("0", sample_tree_a(), [OnB, OnD]),
      ("1", sample_tree_b(), [OnC, OnA]),
    ] |> list.map(fn (params) { get_distribution(params.1st, params.2nd, params.3rd) })
      |> transform_distributions
  let redeemers =
    list.map(
      distributions,
      fn (dist) { MintDistributionRedeemer(dist.datum.id, dist.claim) }
    )
  let outputs =
    [
      Output(distributor_address, assets.from_lovelace(2000000000), NoDatum, None),
      ..list.map(
        distributions,
        fn (dist) {
          Output(
            script_address(),
            assets.from_lovelace(2000000)
              |> assets.add(reward_policy_id, reward_asset_name, dist.amount)
              |> assets.add(own_policy_id, dist.datum.id, 1)
              |> transform_output_value,
            InlineDatum(dist.datum |> transform_output_datum),
            None
          )
        }
      )
    ]
  let mint_value =
    list.foldl(
      distributions,
      assets.zero,
      fn (x, acc) { 
        assets.add(acc, own_policy_id, x.datum.id, 1)
      }
    ) |> transform_mint_value

  validate_mint(redeemers, outputs, mint_value, own_policy_id)
}

test mint_succeeds() {
  test_mint(id, id, id, id)
}

test mint_fails_with_bad_claim() {
  !test_mint(
    fn(distributions) {
      expect Some(first_distribution) = list.head(distributions)
      list.map(
        distributions,
        fn(distribution) {
          Distribution{..distribution, claim: first_distribution.claim}
        }
      )
    },
    id,
    id,
    id
  )
}

test mint_fails_with_incorrect_rewards() {
  !test_mint(
    id,
    assets.add(_, reward_policy_id, reward_asset_name, 1),
    id,
    id
  )
}

test mint_fails_with_stt_redirected() {
  !test_mint(id, remove_policy(_, own_policy_id), id, id)
}

test mint_fails_with_id_mismatch() {
  !test_mint(id, id, fn (datum) { DistributionDatum{..datum, id: "" } }, id)
}

test mint_fails_with_depth_mismatch() {
  !test_mint(id, id, fn (datum) { DistributionDatum{..datum, depth: 1 } }, id)
}

test mint_fails_with_empty_mint() {
  !test_mint(id, id, id, const_(assets.zero))
}

test mint_fails_with_excess_mint() {
  !test_mint(id, id, id, assets.add(_, own_policy_id, "", 1))
}

fn test_cancel(
  input_datum: DistributionDatum,
  input_value: Value,
  transform_outputs: fn(List<Output>) -> List<Output>
) {
  let distributor_address = Address {
    payment_credential: VerificationKey(distributor),
    stake_credential: None
  }
  let input =
    Output(
      script_address(),
      assets.from_lovelace(2000000) |> assets.merge(input_value),
      InlineDatum(input_datum),
      None
    )
  validate_cancel(distributor_address, input_datum, input, transform_outputs([]))
}

test cancel_succeeds_with_stt_missing() {
  test_cancel(
    DistributionDatum("dist1", "", 4),
    assets.from_asset(reward_policy_id, reward_asset_name, 1000000),
    id
  )
}

test cancel_succeeds_with_id_mismatch() {
  test_cancel(
    DistributionDatum("dist1", "", 4),
    assets.from_asset(own_policy_id, "dist2", 1),
    id
  )
}

test cancel_succeeds_with_distributor_paid() {
  let distribution_id = "dist1"
  let distributor_address = Address {
    payment_credential: VerificationKey(distributor),
    stake_credential: None
  }
  let input_value = 
    assets.from_asset(reward_policy_id, reward_asset_name, 1000000)
      |> assets.add(own_policy_id, distribution_id, 1)

  test_cancel(
    DistributionDatum(distribution_id, "", 4),
    input_value,
    list.push(_, Output(
      distributor_address,
      assets.from_lovelace(2000000) |> assets.merge(input_value),
      NoDatum,
      None,
    ))
  )
}

test cancel_fails_with_stt_present() {
  let distribution_id = "dist1"
  !test_cancel(
    DistributionDatum(distribution_id, "", 4),
    assets.from_asset(reward_policy_id, reward_asset_name, 1000000)
      |> assets.add(own_policy_id, distribution_id, 1),
    id
  )
}

fn test_claim(
  transform_input_value: fn(Value) -> Value,
  transform_output_datum: fn(DistributionDatum) -> DistributionDatum,
  transform_output_value: fn(Value) -> Value,
  transform_mint_value: fn(Value) -> Value,
  transform_claim: fn(Claim) -> Claim
) -> Bool {
  let distribution = get_distribution("dist1", sample_tree_a(), [OnB, OnC])
  let (reward, _spend_index, path) = distribution.claim |> transform_claim
  let recipient_address = Address(VerificationKey(reward.recipient), None)
  let account_id = #"abcd"
  let own_input = 
    Output(
      script_address(),
      assets.from_lovelace(2000000)
        |> assets.add(own_policy_id, distribution.datum.id, 1)
        |> assets.add(reward_policy_id, reward_asset_name, distribution.amount)
        |> transform_input_value,
      InlineDatum(distribution.datum),
      None
    )
  let new_datum =
    DistributionDatum{
      ..distribution.datum,
      root_hash: remove_leaf(path, reward.amount)
    } |> transform_output_datum
  let destroy =
    assets.quantity_of(own_input.value, reward_policy_id, reward_asset_name) == 0
  let mint_value =
    if destroy {
      assets.from_asset(own_policy_id, distribution.datum.id, -1)
    } else {
      assets.zero
    } |> transform_mint_value
  let inputs = []
  let outputs =
    if destroy {
      [Output(recipient_address, own_input.value, NoDatum, None)]
    } else {
      [
        Output(
          recipient_address,
          assets.from_lovelace(2000000)
            |> assets.add(reward_policy_id, reward_asset_name, reward.amount),
          NoDatum,
          None
        ),
        Output(
          own_input.address,
          own_input.value
            |> assets.add(reward_policy_id, reward_asset_name, -reward.amount)
            |> transform_output_value,
          InlineDatum(new_datum),
          None
        ),
        Output(
          Address(Script(account_hash), None),
          assets.zero,
          InlineDatum(Account{
            id: account_id,
            verification_key: "not important",
            pub_key_hash: reward.recipient,
            nonce: 0,
          }),
          None
        )
      ]
    }
  let account_spends: Data = SpendAccounts([
    AccountSpend {
      account: account_id,
      intents: [
        SpendRedeemer(
          NoncedIntent(SignedIntent{
            intent: Intent {
              account: account_id,
              nonce: 0,
              fee: 0,
              payload: ExchangeIntent {
                offer: [],
                demand: [Pair(reward_policy_id, [Pair(reward_asset_name, reward.amount)])]
              },
              partial: False,
            },
            protected: "",
            external_aad: "",
            hashed: False,
            indefinite_bytestring: False,
            signature: ""
          }),
          None
        )
      ]
    }
  ])
  let redeemers = [
    Pair(
      Withdraw(Script(account_hash)), 
      account_spends
    )
  ]

  validate_claim(
    distribution.datum,
    distribution.claim,
    own_input,
    account_hash,
    inputs,
    outputs,
    mint_value,
    redeemers,
  )
}

test claim_succeeds() {
  test_claim(id, id, id, id, id)
}

test claim_fails_with_stt_missing() {
  !test_claim(remove_policy(_, own_policy_id), id, id, id, id)
}

test claim_destroy_succeeds() {
  test_claim(remove_policy(_, reward_policy_id), id, id, id, id)
}

test claim_destroy_fails_with_stt_not_burned() {
  !test_claim(
    remove_policy(_, reward_policy_id),
    id,
    id,
    const_(assets.zero),
    id
  )
}

test claim_fails_with_stt_redirected() {
  !test_claim(id, id, remove_policy(_, own_policy_id), id, id)
}

test claim_fails_with_rewards_redirected() {
  !test_claim(
    id,
    id,
    assets.add(_, reward_policy_id, reward_asset_name, -1),
    id,
    id
  )
}

test claim_fails_with_incorrect_root_hash() {
  !test_claim(
    id,
    fn(datum) { DistributionDatum{..datum, root_hash: "" } },
    id,
    id,
    id
  )
}

test claim_fails_with_incorrect_amount() {
  !test_claim(
    id,
    id,
    assets.add(_, reward_policy_id, reward_asset_name, -1),
    id,
    fn (claim) {
      let (reward, spend_index, path) = claim
      (Reward{..reward, amount: reward.amount + 1}, spend_index, path)
    }
  )
}
