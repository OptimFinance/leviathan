use aiken/collection/list
use cardano/transaction.{Input, Transaction, OutputReference, find_input}
use cardano/address.{Address, VerificationKey}
use cardano/assets.{PolicyId}

use account/types.{KeyHash, ScriptHash} as account_types

use distribution/types.{
  Cancel,
  Claim,
  DistributionDatum,
  DistributionRedeemer,
  MintDistributionRedeemer,
}
use distribution/validation.{validate_cancel, validate_claim, validate_mint}

validator distribution(
  distributor: Address,
  sequencer: KeyHash,
  account_script: ScriptHash,
) {
  mint(redeemers: List<MintDistributionRedeemer>, own_policy_id: PolicyId, self: Transaction) -> Bool {
    expect VerificationKey(distributor_pkh) = distributor.payment_credential
    list.has(self.extra_signatories, distributor_pkh)?
      && validate_mint(redeemers, self.outputs, self.mint, own_policy_id)?
  }

  spend(
    datum: Option<DistributionDatum>,
    redeemer: DistributionRedeemer,
    own_out_ref: OutputReference,
    self: Transaction,
  ) -> Bool {
    expect Some(Input{output: own_input, ..}) = find_input(self.inputs, own_out_ref)

    expect list.has(self.extra_signatories, sequencer)
    when (datum, redeemer) is {
      (None, _) -> True
      (Some(datum), Cancel) -> validate_cancel(distributor,  datum, own_input, self.outputs)
      (Some(datum), Claim{claim}) -> {
        validate_claim(
          datum,
          claim,
          own_input,
          account_script,
          self.inputs,
          self.outputs,
          self.mint,
          self.redeemers,
        )
      }
    }
  }
}
