use cardano/transaction.{Transaction,OutputReference}
use cardano/assets.{PolicyId}
use account/types.{
  ApprovedApprovalDatum,
  ApprovedApprovalRedeemer,
  IdMintRedeemer,
  Id,
}
use account/utils.{id_spent, burn_own_id, mint_own_id}

validator approved_approval(key: Id) {
  mint(redeemer: IdMintRedeemer, own_policy_id: PolicyId, self: Transaction) -> Bool {
    and{
      id_spent(key, self.inputs),
      mint_own_id(redeemer, own_policy_id, self, fn(_, _) { True })
    }
  }

  spend(
    _datum: Option<ApprovedApprovalDatum>,
    _redeemer: ApprovedApprovalRedeemer,
    own_input_ref: OutputReference,
    self: Transaction
  ) -> Bool {
    id_spent(key, self.inputs) && burn_own_id(own_input_ref, self)
  }
}
