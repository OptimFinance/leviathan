use aiken/primitive/bytearray
use aiken/cbor
use aiken/crypto.{Blake2b_256, Hash, blake2b_256}
use aiken/collection/list
use distribution/types.{MerkleStep, Proof}

fn calculate_root_hash(
  data_hash: Hash<Blake2b_256, Data>,
  path: Proof,
) -> Hash<Blake2b_256, Data> {
  when path is {
    [] -> data_hash
    [MerkleStep { prefix, suffix, amount }, ..rest] -> {
      let parent_hash =
        prefix
          |> bytearray.concat(data_hash)
          |> bytearray.concat(suffix)
          |> bytearray.concat(cbor.serialise(amount))
          |> blake2b_256
      calculate_root_hash(parent_hash, rest)
    }
  }
}

fn claim_amount(step: MerkleStep, claimed: Int) {
  let new_amount = step.amount - claimed
  if new_amount < 0 {
    fail @"tried to claim more than available"
  } else if claimed < 0 {
    fail @"tried to claim negative amount"
  } else {
    MerkleStep { ..step, amount: new_amount }
  }
}

pub fn verify_leaf(
  leaf_data: Data,
  root_hash: Hash<Blake2b_256, Data>,
  path: Proof,
) -> Bool {
  root_hash == calculate_root_hash(blake2b_256(cbor.serialise(leaf_data)), path)
}

pub fn remove_leaf(
  path: Proof,
  claimed: Int,
) -> Hash<Blake2b_256, Data> {
  calculate_root_hash("", list.map(path, claim_amount(_, claimed)))
}
