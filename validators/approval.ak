use aiken/collection/list
use aiken/collection/dict
use cardano/assets.{PolicyId}
use cardano/transaction.{
  Output,
  OutputReference,
  Transaction
}
use cardano/address.{Script}
use cardano/assets
use account/types.{
  ApprovalDatum,
  ApprovalRedeemer,
  IdMintRedeemer,
  ScriptHash
}
use account/utils.{get_output_datum, burn_own_id, mint_own_id}

validator approval(approved_approvals: ScriptHash) {
  mint(redeemer: IdMintRedeemer, own_policy_id: PolicyId, self: Transaction) -> Bool {
    let valid_approval_output = fn(output: Output, tx_info: Transaction) {
      expect datum: ApprovalDatum = get_output_datum(output, tx_info.datums)

      let has_approved_reference =
        list.any(
          tx_info.reference_inputs,
          fn(input) {
            let output = input.output

            and{
              output.address.payment_credential == Script(approved_approvals),
              dict.values(assets.tokens(output.value, approved_approvals)) == [1]
            }
          }
        )

      and{
        list.has(tx_info.extra_signatories, datum.owner),
        has_approved_reference?
      }
    }

    mint_own_id(redeemer, own_policy_id, self, valid_approval_output)
  }

  spend(datum: Option<ApprovalDatum>, _redeemer: ApprovalRedeemer, own_input_ref: OutputReference, self: Transaction) -> Bool {
    expect Some(approval_datum) = datum
    list.has(self.extra_signatories, approval_datum.owner) && burn_own_id(own_input_ref, self)?
  }
}
