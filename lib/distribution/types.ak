use aiken/crypto.{Blake2b_256, Hash}

use account/types.{KeyHash}

pub type MerkleStep {
  prefix: ByteArray,
  suffix: ByteArray,
  amount: Int,
}

pub type Proof = List<MerkleStep>

pub type Reward {
  recipient: KeyHash,
  amount: Int,
}

pub type Claim = (Reward, Int, Proof)

pub type DistributionDatum {
  id: ByteArray,
  root_hash: Hash<Blake2b_256, ByteArray>,
  depth: Int,
}

pub type DistributionRedeemer {
  Claim { claim: Claim }
  Cancel
}

pub type MintDistributionRedeemer {
  id: ByteArray,
  sample: Claim
}
