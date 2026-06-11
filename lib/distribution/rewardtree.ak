use aiken/primitive/bytearray
use aiken/cbor
use aiken/crypto.{Hash, Blake2b_256, blake2b_256}
use aiken/collection/list
use distribution/quadtree.{QuadTree, QuadSelect, QuadLeaf, QuadNode}
use distribution/types.{Reward, MerkleStep}

pub fn total_amount(tree: QuadTree<Reward>) -> Int {
  quadtree.foldl(tree, 0, fn(x, a) { x + a }, fn(reward) { reward.amount })
}

// TODO: generalise
pub fn hash(tree: QuadTree<Reward>) -> Hash<Blake2b_256, Data> {
  when tree is {
    QuadLeaf { value: None } -> ""
    QuadLeaf{value: Some(value)} -> blake2b_256(cbor.serialise(value))
    QuadNode { a, b, c, d } ->
      [a, b, c, d]
        |> list.foldl("", fn(x, a) { bytearray.concat(a, hash(x)) })
        |> bytearray.concat(cbor.serialise(total_amount(tree)))
        |> blake2b_256
  }
}

pub fn mk_step(
  parent: QuadTree<Reward>,
  before: List<QuadTree<Reward>>,
  after: List<QuadTree<Reward>>
) -> MerkleStep {
  let concat_hashes =
    fn(branches) {
      list.foldl(branches, "", fn(x, a) { bytearray.concat(a, hash(x)) })
    }
  let prefix = concat_hashes(before)
  let suffix = concat_hashes(after)
  MerkleStep(prefix, suffix, total_amount(parent))
}

pub fn step_path(
  prev: (QuadTree<Reward>, List<MerkleStep>),
  selector: QuadSelect
) -> (QuadTree<Reward>, List<MerkleStep>) {
  quadtree.step_path(prev, selector, mk_step)
}
