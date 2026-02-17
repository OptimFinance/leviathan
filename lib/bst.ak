use aiken/math.{max}

pub type BST<key, value> {
  Leaf
  Node {
      key: key,
      value: value,
      left: BST<key, value>,
      right: BST<key, value>,
      height: Int
  }
}

fn height(tree: BST<key, value>) -> Int {
  when tree is {
    Leaf -> 0
    Node { height, .. } -> height
  }
}

fn update_height(tree: BST<key, value>) -> BST<key, value> {
  when tree is {
    Leaf -> Leaf
    Node { key, value, left, right, .. } -> {
      let h = max(height(left), height(right)) + 1
      Node { key, value, left, right, height: h }
    }
  }
}

fn balance_factor(tree: BST<key, value>) -> Int {
  when tree is {
    Leaf -> 0
    Node { left, right, .. } -> height(left) - height(right)
  }
}

fn left_rotate(tree: BST<key, value>) -> BST<key, value> {
  when tree is {
    Node { key, value, left, right, .. } ->
      when right is {
        Node { key: rk, value: rv, left: rl, right: rr, .. } -> {
          let new_left = update_height(Node { key, value, left, right: rl, height: 0 })
          let new_root = update_height(Node { key: rk, value: rv, left: new_left, right: rr, height: 0 })
          new_root
        }
        _ -> tree
      }
    _ -> tree
  }
}

fn right_rotate(tree: BST<key, value>) -> BST<key, value> {
  when tree is {
    Node { key, value, left, right, .. } ->
      when left is {
        Node { key: lk, value: lv, left: ll, right: lr, .. } -> {
          let new_right = update_height(Node { key, value, left: lr, right, height: 0 })
          let new_root = update_height(Node { key: lk, value: lv, left: ll, right: new_right, height: 0 })
          new_root
        }
        _ -> tree
      }
    _ -> tree
  }
}

fn balance_tree(tree: BST<key, value>) -> BST<key, value> {
  when tree is {
    Leaf -> Leaf
    Node { left, right, key, value, .. } -> {
      let bf = balance_factor(tree)
      if bf > 1 {
        if balance_factor(left) < 0 {
          let left_rotated = left_rotate(left)
          let node_lr = Node { key, value, left: left_rotated, right, height: 0 }
          right_rotate(node_lr)
        } else {
          right_rotate(tree)
        }
      } else if bf < -1 {
        if balance_factor(right) > 0 {
          let right_rotated = right_rotate(right)
          let node_rl = Node { key, value, left, right: right_rotated, height: 0 }
          left_rotate(node_rl)
        } else {
          left_rotate(tree)
        }
      } else {
        update_height(tree)
      }
    }
  }
}

pub fn insert(
  tree: BST<key, value>,
  key: key,
  value: value,
  cmp: fn (key, key) -> Ordering
) -> BST<key, value> {
  let new_tree = when tree is {
    Leaf -> {
      Node { key, value, left: Leaf, right: Leaf, height: 1 }
    }
    Node { key: k, value: v, left, right, .. } -> {
      let (new_left, new_right) = when cmp(key, k) is {
        Less -> {
          let l = insert(left, key, value, cmp)
          (l, right)
        }
        _ -> {
          let r = insert(right, key, value, cmp)
          (left, r)
        }
      }
      Node { key: k, value: v, left: new_left, right: new_right, height: 0 }
    }
  }
  balance_tree(new_tree)
}

pub fn lookup(
  tree: BST<key, value>,
  key: key,
  cmp: fn (key, key) -> Ordering
) -> Option<value> {
  when tree is {
    Leaf -> None
    Node { key: k, value: v, left, right, .. } ->
      when cmp(key, k) is {
        Equal -> Some(v)
        Less -> lookup(left, key, cmp)
        Greater -> lookup(right, key, cmp)
      }
  }
}

pub fn update(
  tree: BST<key, value>,
  key: key,
  f: fn (value) -> value,
  cmp: fn (key, key) -> Ordering
) -> BST<key, value> {
  when tree is {
    Leaf -> Leaf
    Node { key: k, value: v, left, right, height } ->
      when cmp(key, k) is {
        Equal -> Node {
          key: k,
          value: f(v),
          left, right,
          height
        }
        Less -> Node {
          key: k,
          value: v,
          left: update(left, key, f, cmp),
          right: right,
          height: height
        }
        Greater -> Node {
          key: k,
          value: v,
          left: left, 
          right: update(right, key, f, cmp),
          height: height
        }
      }
  }
}

pub fn update_and_test(
  tree: BST<key, value>,
  key: key,
  f: fn (value) -> value,
  pred: fn (value) -> Bool,
  cmp: fn (key, key) -> Ordering
) -> (Bool, BST<key, value>) {
  when tree is {
    Leaf -> (False, Leaf)
    Node { key: k, value: v, left, right, height } ->
      when cmp(key, k) is {
        Equal -> {
          let new_value = f(v)
          (pred(new_value), Node {
            key: k,
            value: new_value,
            left, right,
            height
          })
        }
        Less -> {
          let (p, new) = update_and_test(left, key, f, pred, cmp)
          (p, Node {
            key: k,
            value: v,
            left: new,
            right: right,
            height: height
          })
        }
        Greater -> {
          let (p, new) = update_and_test(right, key, f, pred, cmp)
          (p, Node {
            key: k,
            value: v,
            left: left, 
            right: new,
            height: height
          })
        }
      }
  }
}
