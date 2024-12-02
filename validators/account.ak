use aiken/list
use aiken/dict.{Dict}
use aiken/transaction.{
  Input,
  Output,
  ScriptContext,
  ScriptPurpose,
  Spend,
  Transaction,
  WithdrawFrom
}
use aiken/transaction/credential.{
  Inline,
  ScriptCredential,
}
use aiken/transaction/value
use account/types.{
  AccountDatum,
  AccountAddress,
  AccountRedeemer,
  ApprovedApprovalDatum,
  ApprovedId,
  ApprovalDatum,
  ApprovedIntentAnnouncer,
  DataMap,
  FundAccount,
  IdMintRedeemer,
  IntentActionsRedeemer,
  MoveTokens,
  RawAddress,
  ScriptHash,
  SpendAccount,
}
use account/utils.{
  get_output_datum,
  value_has_policy,
  input_has_own_id,
  mint_own_id
}

fn validate_fund(
  datum: AccountDatum,
  own_output: Output,
  approved_approvals: ScriptHash,
  reference_inputs: List<Input>,
  datums: DataMap
) -> Bool {
  // NOTE: could split intent hash updating to another redeemer
  let update_intent_hash = fn(old_datum: AccountDatum, new_datum: AccountDatum) {
    let expected_datum = AccountDatum(
      old_datum.account_id,
      old_datum.owner,
      old_datum.verification_key,
      old_datum.nonce,
      new_datum.intent_hash
    )

    let intent_announcer_unchanged =
      old_datum.intent_hash == new_datum.intent_hash

    let new_intent_announcer_approved =
      list.any(
        reference_inputs,
        fn (input) {
          let output = input.output
          expect ref_datum: ApprovedApprovalDatum = get_output_datum(output, datums)

          and{
            output.address.payment_credential == ScriptCredential(approved_approvals),
            value_has_policy(output.value, approved_approvals)?,
            ref_datum.approved == ApprovedIntentAnnouncer(new_datum.intent_hash)
          }
        }
      )

    let valid_intent =
      or{
        intent_announcer_unchanged,
        new_intent_announcer_approved
      }?

    and{
      (new_datum == expected_datum)?,
      valid_intent
    }
  }

  expect out_datum: AccountDatum = get_output_datum(own_output, datums)
  update_intent_hash(datum, out_datum)
}

fn validate_spend(
  datum: AccountDatum,
  own_input: Input,
  own_output: Output,
  approvals_map: ScriptHash,
  always_succeeds: ScriptHash,
  redeemers: Dict<ScriptPurpose, Data>,
  reference_inputs: List<Input>,
  datums: DataMap
) -> Bool {
  expect out_datum: AccountDatum = get_output_datum(own_output, datums)
  expect Some(intents_redeemer) = dict.get(redeemers, WithdrawFrom(Inline(ScriptCredential(datum.intent_hash))))
  expect IntentActionsRedeemer(intents, actions): IntentActionsRedeemer = intents_redeemer

  let account_intents =
    list.filter(intents, fn(intent) {intent.account_id == datum.account_id})

  let (priority_fee, nonce_increment) = 
    list.foldl(
      account_intents,
      (0, 0),
      fn (intent, acc) {
        let (fee, inc) = acc
        (fee + intent.fee, inc + 1)
      }
    )

  let action_approved = fn(action) {
    let MoveTokens(app_id, _tokens, _sender, _recipient) = action
    list.any(
      reference_inputs,
      fn(input) {
        expect datum: ApprovalDatum = get_output_datum(input.output, datums)

        and{
          input.output.address.payment_credential == ScriptCredential(approvals_map),
          input_has_own_id(input),
          datum.approved == ApprovedId(app_id)
        }
      }
    )
  }

  let expected_datum =
    AccountDatum(
      datum.account_id,
      datum.owner,
      datum.verification_key,
      datum.nonce + nonce_increment,
      datum.intent_hash
    )

  let value_delta = value.merge(own_input.output.value, value.negate(own_output.value))

  let fee_value = value.from_lovelace(3000000 + priority_fee)

  expect [action] = actions
  let expected_action = 
    if priority_fee > 0 {
      MoveTokens(
        datum.account_id,
        fee_value,
        AccountAddress(datum.account_id),
        RawAddress(ScriptCredential(always_succeeds))
      )
    } else {
      MoveTokens(
        datum.account_id,
        fee_value,
        AccountAddress(datum.account_id),
        action.recipient
      )
    }

  and{
    input_has_own_id(own_input)?,
    list.all(actions, action_approved)?,
    (out_datum == expected_datum)?,
    (value_delta == fee_value)?,
    (action == expected_action)?
  }
}

validator (approvals_map: ScriptHash, approved_approvals: ScriptHash, always_succeeds: ScriptHash) {
  fn mint(redeemer: IdMintRedeemer, ctx: ScriptContext) -> Bool {
    let valid_account_output = fn(output: Output, tx_info: Transaction) {
      expect datum: AccountDatum = get_output_datum(output, tx_info.datums)
      list.has(tx_info.extra_signatories, datum.owner) && datum.nonce == 0
    }
    
    mint_own_id(redeemer, ctx, valid_account_output)
  }

  fn spend(datum: AccountDatum, redeemer: AccountRedeemer, ctx: ScriptContext) -> Bool {
    let ScriptContext(tx_info, purpose) = ctx
    expect Spend(own_input_ref) = purpose
    expect Some(own_input) = 
      list.find(
        tx_info.inputs,
        fn (input) { input.output_reference == own_input_ref }
      )

    // FIXME: currently only considering a single account output
    expect Some(own_output) = 
      list.find(
        tx_info.outputs,
        fn (output) { output.address == own_input.output.address }
      )

      when redeemer is {
        FundAccount() ->
          list.has(tx_info.extra_signatories, datum.owner) &&
            validate_fund(
              datum,
              own_output,
              approved_approvals,
              tx_info.reference_inputs,
              tx_info.datums
            ) 
        SpendAccount() ->
          validate_spend(
            datum,
            own_input,
            own_output,
            approvals_map,
            always_succeeds,
            tx_info.redeemers,
            tx_info.reference_inputs,
            tx_info.datums
          )
      }
  }
}
