use aiken/transaction.{
  ScriptContext,
}
use account/types.{
  ApprovedApprovalDatum,
  ApprovedApprovalRedeemer,
  IdMintRedeemer,
  Id,
}
use account/utils.{id_spent, burn_own_id, mint_own_id}

validator (key: Id) {
  fn mint(redeemer: IdMintRedeemer, ctx: ScriptContext) -> Bool {
    and{
      id_spent(key, ctx.transaction.inputs),
      mint_own_id(redeemer, ctx, fn(_, _) { True })
    }
  }

  fn spend(
    _datum: ApprovedApprovalDatum,
    _redeemer: ApprovedApprovalRedeemer,
    ctx: ScriptContext
  ) -> Bool {
    id_spent(key, ctx.transaction.inputs) && burn_own_id(ctx)
  }
}
