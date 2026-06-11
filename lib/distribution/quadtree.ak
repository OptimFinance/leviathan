use aiken/collection/list
use aiken/math.{max}

pub type QuadTree<t> {
  QuadNode { a: QuadTree<t>, b: QuadTree<t>, c: QuadTree<t>, d: QuadTree<t> }
  QuadLeaf { value: Option<t> }
}

pub type QuadSelect {
  OnA
  OnB
  OnC
  OnD
}

pub fn foldl(
  tree: QuadTree<t>,
  zero: b,
  with: fn(b, b) -> b,
  extract: fn(t) -> b,
) -> b {
  when tree is {
    QuadLeaf { value: None } -> zero
    QuadLeaf{value: Some(leafValue)} -> extract(leafValue)
    QuadNode { a, b, c, d } ->
      list.foldl(
        [a, b, c, d],
        zero,
        fn(x, acc) { with(foldl(x, zero, with, extract), acc) }
      )
  }
}

fn depth_(branch: QuadTree<t>, n: Int) -> Int {
  when branch is {
    QuadLeaf { .. } -> n
    QuadNode { a, b, c, d } ->
      depth_(a, n + 1)
        |> max(depth_(b, n + 1))
        |> max(depth_(c, n + 1))
        |> max(depth_(d, n + 1))
  }
}

pub fn depth(tree: QuadTree<t>) -> Int { depth_(tree, 0) }

pub fn empty(depth: Int) -> QuadTree<t> {
  if (depth <= 0) {
    QuadLeaf(None)
  } else {
    let empty_branch = empty(depth - 1)
    QuadNode(empty_branch, empty_branch, empty_branch, empty_branch)
  }
}

pub fn split(
  node: QuadTree<t>,
  selector: QuadSelect
) -> (List<QuadTree<t>>, QuadTree<t>, List<QuadTree<t>>) {
  expect QuadNode { a, b, c, d } = node
  when selector is {
    OnA -> ([], a, [b, c, d])
    OnB -> ([a], b, [c, d])
    OnC -> ([a, b], c, [d])
    OnD -> ([a, b, c], d, [])
  }
}

pub fn select(tree: QuadTree<t>, selection: List<QuadSelect>) -> QuadTree<t> {
  list.foldl(selection, tree, fn(s, n) { split(n, s).2nd })
}

pub fn remove(tree: QuadTree<t>, selection: List<QuadSelect>) -> QuadTree<t> {
  when selection is {
    [] -> QuadLeaf(None)
    [selector, ..selectors] -> {
      expect QuadNode { a, b, c, d } = tree
      when selector is {
        OnA -> QuadNode(remove(a, selectors), b, c, d)
        OnB -> QuadNode(a, remove(b, selectors), c, d)
        OnC -> QuadNode(a, b, remove(c, selectors), d)
        OnD -> QuadNode(a, b, c, remove(d, selectors))
      }
    }
  }
}

pub fn init_path(tree: QuadTree<t>) -> (QuadTree<t>, List<s>) {
  (tree, [])
}

pub fn step_path(
  prev: (QuadTree<t>, List<s>),
  selector: QuadSelect,
  with: fn(QuadTree<t>, List<QuadTree<t>>, List<QuadTree<t>>) -> s
) -> (QuadTree<t>, List<s>) {
  let (parent, steps) = prev
  let (before, child, after) = split(parent, selector)

  (child, [with(parent, before, after), ..steps])
}
