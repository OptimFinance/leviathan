use aiken/primitive/bytearray
use aiken/collection/list
use distribution/merkle.{remove_leaf, verify_leaf}
use distribution/types.{MerkleStep, Reward}
use distribution/utils.{or_}
use distribution/quadtree.{QuadTree, QuadNode, QuadLeaf, OnA, OnB, OnC, OnD}
use distribution/rewardtree

fn sample_tree() {
  QuadNode(
    QuadNode(
      QuadLeaf(Some(Reward(#"aa", 1))),
      QuadLeaf(Some(Reward(#"ab", 2))),
      QuadLeaf(Some(Reward(#"ac", 3))),
      QuadLeaf(Some(Reward(#"ad", 4))),
    ),
    QuadNode(
      QuadLeaf(Some(Reward(#"ba", 1))),
      QuadLeaf(Some(Reward(#"bb", 2))),
      QuadLeaf(Some(Reward(#"bc", 3))),
      QuadLeaf(None),
    ),
    QuadNode(
      QuadLeaf(Some(Reward(#"ca", 1))),
      QuadLeaf(None),
      QuadLeaf(Some(Reward(#"cc", 3))),
      QuadLeaf(Some(Reward(#"cd", 4))),
    ),
    QuadNode(
      QuadLeaf(Some(Reward(#"da", 1))),
      QuadLeaf(Some(Reward(#"db", 2))),
      QuadLeaf(Some(Reward(#"dc", 3))),
      QuadLeaf(Some(Reward(#"dd", 4))),
    ),
  )
}

test merkle_path_verifies() {
  let tree = sample_tree()
  expect QuadNode { a: treeA, b: treeB, c: treeC, d: treeD } = tree
  expect QuadNode { a: treeAA, b: treeAB, c: treeAC, d: treeAD } = treeA
  expect QuadLeaf{value: Some(leafValue)} = treeAC
  let path =
    [
      MerkleStep(
        rewardtree.hash(treeAA) |> bytearray.concat(rewardtree.hash(treeAB)),
        rewardtree.hash(treeAD),
        rewardtree.total_amount(treeA),
      ),
      MerkleStep(
        "",
        rewardtree.hash(treeB)
          |> bytearray.concat(rewardtree.hash(treeC))
          |> bytearray.concat(rewardtree.hash(treeD)),
        rewardtree.total_amount(tree),
      ),
    ]
  verify_leaf(leafValue, rewardtree.hash(tree), path)
}

test merkle_path_invalid_path_to_node() {
  let tree = sample_tree()
  expect QuadNode { a: treeA, b: treeB, c: treeC, d: treeD } = tree
  expect QuadNode { a: treeAA, b: treeAB, d: treeAD, .. } = treeA
  expect QuadLeaf{value: Some(leafValue)} = treeAD
  let path =
    [
      MerkleStep(
        rewardtree.hash(treeAA) |> bytearray.concat(rewardtree.hash(treeAB)),
        rewardtree.hash(treeAD),
        rewardtree.total_amount(treeA),
      ),
      MerkleStep(
        "",
        rewardtree.hash(treeB)
          |> bytearray.concat(rewardtree.hash(treeC))
          |> bytearray.concat(rewardtree.hash(treeD)),
        rewardtree.total_amount(tree),
      ),
    ]
  !verify_leaf(leafValue, rewardtree.hash(tree), path)
}

test merkle_path_removes() {
  let treeBefore = sample_tree()
  expect QuadNode { a: treeA, b: treeB, c: treeC, d: treeD } = treeBefore
  expect QuadNode { a: treeAA, b: treeAB, c: treeAC, d: treeAD } = treeA
  expect QuadLeaf{value: Some(Reward { amount: claimed_amount, .. })} = treeAC
  let treeAfter =
    QuadNode(QuadNode(treeAA, treeAB, QuadLeaf(None), treeAD), treeB, treeC, treeD)
  let path =
    [
      MerkleStep(
        rewardtree.hash(treeAA)
          |> bytearray.concat(rewardtree.hash(treeAB)),
        rewardtree.hash(treeAD),
        rewardtree.total_amount(treeA),
      ),
      MerkleStep(
        "",
        rewardtree.hash(treeB)
          |> bytearray.concat(rewardtree.hash(treeC))
          |> bytearray.concat(rewardtree.hash(treeD)),
        rewardtree.total_amount(treeBefore),
      ),
    ]
  remove_leaf(path, claimed_amount) == rewardtree.hash(treeAfter)
}

fn claim_all(claims, tree: QuadTree<Reward>) -> Bool {
  when claims is {
    [] -> tree == quadtree.empty(quadtree.depth(tree))
    [claim, ..claims0] -> {
      let root_hash = rewardtree.hash(tree)
      let (node, path) =
        list.foldl(
          claim,
          quadtree.init_path(tree),
          fn(x, a) { a |> rewardtree.step_path(x)}
        )
      expect QuadLeaf{value: Some(leafValue)} = node
      verify_leaf(leafValue, root_hash, path) && claim_all(
        claims0,
        quadtree.remove(tree, claim),
      )
    }
  }
}

test merkle_claim_all() {
  let tree = sample_tree()
  let claims =
    [ [OnC, OnA], [OnA, OnD], [OnB, OnD], [OnC, OnD],
      [OnB, OnB], [OnD, OnA], [OnA, OnA], [OnA, OnB],
      [OnC, OnB], [OnD, OnD], [OnD, OnB], [OnB, OnA],
      [OnD, OnC], [OnB, OnC], [OnA, OnC], [OnC, OnC],
    ]
  let non_empty_claims =
    list.filter(claims, fn(s) { quadtree.select(tree, s) != QuadLeaf(None) })
  claim_all(non_empty_claims, tree)
}

test merkle_verify_and_remove_exunits() {
  let z256 =
    "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
  let z512 =
    "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
  let z768 =
    "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
  let z28 = "zzzzzzzzzzzzzzzzzzzzzzzzzzzz"
  let amount = 100
  let path =
    [
      MerkleStep(z256, z512, amount),
      MerkleStep(z512, z256, amount),
      MerkleStep("", z768, amount),
      MerkleStep(z768, "", amount),
      MerkleStep("", z512, amount),
      MerkleStep(z512, "", amount),
      MerkleStep(z256, "", amount),
      MerkleStep("", z256, amount),
      MerkleStep(z256, z256, amount),
      MerkleStep(z768, "", amount),
    ]
  or_(
    [
      verify_leaf(Reward(z28, amount), "", path),
      remove_leaf(path, amount) == "",
      True,
    ],
  )
}
