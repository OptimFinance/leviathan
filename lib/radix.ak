use aiken/collection/list
use aiken/primitive/bytearray
use aiken/option
use aiken/math.{min}

pub type Radix<t> {
  prefix: ByteArray,
  value: Option<t>,
  children: List<Radix<t>>
}

pub fn empty() {
  Radix { prefix: "", value: None, children: [] }
}

fn insert_next(
  key: ByteArray,
  value: t,
  next: Radix<t>,
  rest: List<Radix<t>>,
  acc: List<Radix<t>>,
  update: fn (t, t) -> t,
) {
  let head = bytearray.at(key, 0)
  let next_head = bytearray.at(next.prefix, 0)
  if (next_head == head) {
    let new_child = upsert(next, key, value, update)
    list.concat(acc, list.push(rest, new_child))
  } else if (next_head > head) {
    let new_child = Radix {
      prefix: key,
      value: Some(value),
      children: []
    }
    list.concat(acc, list.push(list.push(rest, next), new_child))
  } else {
    when rest is {
      [] -> list.concat(acc, [next, Radix { prefix: key, value: Some(value), children: [] }])
      [next_next, ..rest_rest] -> {
        insert_next(key, value, next_next, rest_rest, list.concat(acc, [next]), update)
      }
    }
  }
}

fn insert_child(key: ByteArray, value: t, entries: List<Radix<t>>, update: fn (t, t) -> t) {
  let result = when entries is {
    [next, ..rest] -> insert_next(key, value, next, rest, [], update)
    [] -> [
      Radix {
        prefix: key,
        value: Some(value),
        children: []
      }
    ]
  }

  result
}

pub fn upsert(
  tree: Radix<t>,
  key: ByteArray,
  value: t,
  update: fn (t, t) -> t,
) -> Radix<t> {
  let Radix { prefix: p, value: v, children: c } = tree
  let common_length = common_prefix_length(p, key)
  
  if common_length < bytearray.length(p) {
    let old_prefix = bytearray.drop(p, common_length)
    let new_prefix = bytearray.drop(key, common_length)
  
    let old_child = Radix {
      prefix: old_prefix,
      children: c,
      value: v,
    }
    let new_child = Radix {
      prefix: new_prefix,
      value: Some(value),
      children: []
    }

    Radix {
      prefix: bytearray.take(p, common_length),
      value: None,
      children: if bytearray.compare(old_prefix, new_prefix) == Less {
        [old_child, new_child]
      } else {
        [new_child, old_child]
      }
    }
  } else if common_length < bytearray.length(key) {
    let remaining_key = bytearray.drop(key, common_length)
    let common = bytearray.take(key, common_length)
  
    Radix {
      prefix: common,
      value: v,
      children: insert_child(remaining_key, value, c, update)
    }
  } else {
    Radix {
      prefix: p,
      value: when v is {
        Some(v) -> Some(update(v, value))
        None -> Some(value)
      },
      children: c
    }
  }
}

pub fn insert(
  tree: Radix<t>,
  key: ByteArray,
  value: t,
  _cmp: fn (ByteArray, ByteArray) -> Ordering
) -> Radix<t> {
  upsert(tree, key, value, fn (_, value) { value })
}

pub fn lookup(tree: Radix<t>, key: ByteArray) -> Option<t> {
  let Radix { prefix: p, value: v, children: c } = tree
  let common_length = common_prefix_length(p, key)
  
  if common_length < bytearray.length(p) {
    None
  } else if common_length < bytearray.length(key) {
    let remaining_key = bytearray.drop(key, common_length)
    list.find(
      c,
      fn (child) { bytearray.starts_with(remaining_key, child.prefix) }
    ) |> option.and_then(fn (child) { lookup(child, remaining_key) })
  } else {
    v
  }
}

fn common_prefix_helper(a: ByteArray, b: ByteArray, len: Int, pos: Int) -> Int {
  if pos < len {
      let a_byte = bytearray.at(a, pos)
      let b_byte = bytearray.at(b, pos)
      if a_byte == b_byte {
          common_prefix_helper(a, b, len, pos + 1)
      } else {
          pos
      }
  } else {
      len
  }
}

fn common_prefix_length(a: ByteArray, b: ByteArray) -> Int {
    let len = min(bytearray.length(a), bytearray.length(b))
    common_prefix_helper(a, b, len, 0)
}
