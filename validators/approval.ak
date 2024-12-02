use aiken/list
use aiken/dict
use aiken/transaction.{
  Output,
  ScriptContext,
  Transaction
}
use aiken/transaction/credential.{ScriptCredential}
use aiken/transaction/value
use account/types.{
  ApprovalDatum,
  ApprovalRedeemer,
  IdMintRedeemer,
  ScriptHash
}
use account/utils.{get_output_datum, burn_own_id, mint_own_id}

validator (approved_approvals: ScriptHash) {
  fn mint(redeemer: IdMintRedeemer, ctx: ScriptContext) -> Bool {
    let valid_approval_output = fn(output: Output, tx_info: Transaction) {
      expect datum: ApprovalDatum = get_output_datum(output, tx_info.datums)

      let has_approved_reference =
        list.any(
          tx_info.reference_inputs,
          fn(input) {
            let output = input.output

            and{
              output.address.payment_credential == ScriptCredential(approved_approvals),
              dict.values(value.tokens(output.value, approved_approvals)) == [1]
            }
          }
        )

      and{
        list.has(tx_info.extra_signatories, datum.owner),
        has_approved_reference?
      }
    }

    mint_own_id(redeemer, ctx, valid_approval_output)
  }

  fn spend(datum: ApprovalDatum, _redeemer: ApprovalRedeemer, ctx: ScriptContext) -> Bool {
    list.has(ctx.transaction.extra_signatories, datum.owner) && burn_own_id(ctx)?
  }
}
