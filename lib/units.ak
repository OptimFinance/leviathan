use aiken/collection/pairs
use aiken/collection/dict.{Dict}
use aiken/collection/list
use aiken/primitive/bytearray
use aiken/primitive/int
use aiken/fuzz
use aiken/crypto.{blake2b_224}
use aiken/option
use aiken/math.{min, max, log2}
use cardano/assets.{AssetName, PolicyId, Value}
use cardano/transaction.{InlineDatum, Input, NoDatum, Output, OutputReference}

use account/types.{KeyHash}
use bst
use radix
use cardano/address.{Address, Script, VerificationKey}

const account_script = "account_script"
const inbox_script = "inbox_script"

pub fn fuzz_eachl(fuzzer: Fuzzer<List<t>>, empty: r, cb: fn (t, r) -> Fuzzer<r>) -> Fuzzer<r> {
  let v <- fuzz.and_then(fuzzer)
  list.foldl(v, fuzz.constant(empty), fn (t, fr) { fuzz.and_then(fr, cb(t, _)) })
}

pub fn fuzz_eachr(fuzzer: Fuzzer<List<t>>, empty: r, cb: fn (t, r) -> Fuzzer<r>) -> Fuzzer<r> {
  let v <- fuzz.and_then(fuzzer)
  list.foldr(v, fuzz.constant(empty), fn (t, fr) { fuzz.and_then(fr, cb(t, _)) })
}

pub fn fuzz_list_fixed(fuzzer: Fuzzer<t>, size: Int) {
  fuzz.list_between(fuzzer, size, size)
}

fn owner_assets_to_tree(
  assets: Dict<KeyHash, Value>,
  empty: t,
  insert: fn (t, ByteArray, Int, fn (ByteArray, ByteArray) -> Ordering) -> t
) -> t {
  list.foldl(
    dict.to_pairs(assets),
    empty,
    fn (Pair(key_hash, assets), ta) {
      list.foldl(
        dict.to_pairs(assets.to_dict(assets)),
        ta,
        fn (Pair(policy_id, tokens), tb) {
          list.foldl(
            dict.to_pairs(tokens),
            tb,
            fn (Pair(asset_name, quantity), tc) {
              let key = key_hash |> bytearray.concat(policy_id) |> bytearray.concat(asset_name)
              insert(tc, key, quantity, bytearray.compare)
            }
          )
        }
      )
    }
  )
}

pub fn fuzz_tokens(size: Int) -> Fuzzer<Pairs<AssetName, Int>> {
  let tokens <- fuzz.map(fuzz.list_between({
    let token_name, quantity <- fuzz.map2(
      fuzz.bytearray_between(0, 31),
      fuzz.int_at_least(1)
    )
    Pair(token_name, quantity)
  }, max(1, size), min(size, 256)))
  list.indexed_map(tokens, fn (ix, Pair(name, quantity)) { Pair(bytearray.push(name, ix), quantity) })
}

pub fn fuzz_assets(size: Int) -> Fuzzer<Pairs<PolicyId, Pairs<AssetName, Int>>> {
  let assets <- fuzz.map(fuzz.list_between({
    let policy_id, tokens <- fuzz.map2(
      fuzz.bytearray_fixed(27),
      fuzz_tokens(log2(max(1, size)))
    )
    Pair(policy_id, tokens)
  }, max(1, size), min(size, 256)))
  list.indexed_map(
    assets,
    fn (ix, Pair(policy_id, quantity)) { Pair(bytearray.push(policy_id, ix), quantity) }
  )
}

pub fn fuzz_owner_assets(size: Int) -> Fuzzer<Dict<KeyHash, Value>> {
  let owner, result <- fuzz_eachl(
    fuzz.list_at_least(fuzz.bytearray(), size),
    dict.empty
  )
  let lovelace <- fuzz.and_then(fuzz.int_at_least(2_000_000))
  let assets <- fuzz.map(fuzz_assets(log2(max(1, size))))

  dict.insert(
    result,
    owner,
    assets.from_asset_list(list.push(assets, Pair("", [Pair("", lovelace)])))
  )
}

fn fuzz_deltas(size: Int) -> Fuzzer<Dict<KeyHash, Dict<KeyHash, Value>>> {
  let result <- fuzz.map({
    let owner, result <- fuzz_eachl(
      fuzz_list_fixed(fuzz.bytearray_fixed(28), size),
      dict.empty
    )
    
    let sends <- fuzz.map(
      fuzz_list_fixed(fuzz.tuple(fuzz.bool(), fuzz_assets(log2(size))), size)
    )

    let deltas, _ix <- list.foldl2(
      sends,
      [],
      0,
      fn (send, prev, ix, return) {
        if (send.1st) {
          return(pairs.insert_by_ascending_key(prev, ix, assets.from_asset_list(send.2nd), int.compare), ix + 1)
        } else {
          return(prev, ix + 1)
        }
      }
    )

    dict.insert(result, owner, deltas)
  })

  let owners = dict.keys(result)
  
  {
    let Pair(owner, sends) <- list.map(dict.to_pairs(result))
    let deltas = {
      let Pair(ix, value) <- list.map(sends)
      expect Some(to) = list.at(owners, ix)
      Pair(to, value)
    } |> dict.from_pairs
    Pair(owner, deltas)
  } |> dict.from_pairs
}

fn zip_with(xs: List<a>, ys: List<b>, f: fn (a, b) -> c) -> List<c> {
  when (xs, ys) is {
    ([x, ..xs], [y, ..ys]) -> list.push(zip_with(xs, ys, f), f(x, y))
    _ -> []
  }
}

pub fn fuzz_exchange(size: Int) -> Fuzzer<(List<Input>, List<Output>)> {
  let deltas <- fuzz.and_then(fuzz_deltas(size))

  let params <- fuzz.map(fuzz_list_fixed({
    fuzz.tuple4(
      fuzz.int_at_least(2_000_000),
      fuzz_assets(2),
      fuzz.bool(),
      fuzz.bytearray_fixed(32)
    )
  }, size))

  let address = Address {
    payment_credential: Script(account_script),
    stake_credential: None
  }
  let result = zip_with(
    dict.to_pairs(deltas),
    params,
    fn (Pair(owner, sends), (base_lovelace, base_assets, is_account, transaction_id)) {
      let owner_token = assets.from_asset(account_script, owner, 1)
      let base_value =
        assets.from_asset_list(list.push(base_assets, Pair("", [Pair("", base_lovelace)])))
          |> assets.merge(owner_token)

      let sent = list.foldl(dict.values(sends), assets.zero, assets.merge)
      let received = list.foldl(
        dict.to_pairs(deltas),
        assets.zero,
        fn (Pair(sender, sends), acc) {
          if (sender == owner) {
            acc
          } else {
            when dict.get(sends, owner) is {
              Some(receive) -> assets.merge(receive, acc)
              None -> acc
            }
          }
        }
      )

      let input = Input {
        output_reference: OutputReference {
          transaction_id,
          output_index: 0
        },
        output: Output {
          address,
          value: assets.merge(base_value, sent),
          datum: InlineDatum(is_account),
          reference_script: None
        }
      }

      let output = Output {
        address,
        value: assets.merge(base_value, received),
        datum: InlineDatum(is_account),
        reference_script: None
      }

      (input, output)
    }
  )

  let inputs =
    list.map(result, fn (x) { x.1st })
      |> list.sort(_, fn (a: Input, b: Input) {
        bytearray.compare(a.output_reference.transaction_id, b.output_reference.transaction_id)
      })
  let outputs = list.map(result, fn (x) { x.2nd })

  (inputs, outputs)
}

fn fuzz_sync(size: Int) -> Fuzzer<(List<Input>, List<Output>)> {
  let account_address = Address {
    payment_credential: Script(account_script),
    stake_credential: None
  }
  let inbox_address = Address {
    payment_credential: Script(inbox_script),
    stake_credential: None
  }

  let (inputs, outputs) <- fuzz.map({
    let owner, (inputs, outputs) <- fuzz_eachl(fuzz_list_fixed(fuzz.bytearray_fixed(28), size), ([], []))

    let id = assets.from_asset(account_script, owner, 1)
    let lovelace <- fuzz.and_then(fuzz.int_at_least(2_000_000))
    let base_value <- fuzz.and_then(
      fuzz_assets(5)
        |> fuzz.map(_, fn(assets) {
          assets.from_asset_list(assets)
            |> assets.merge(_, assets.from_lovelace(lovelace))
            |> assets.merge(_, id)
        })
    )
    let (incoming_assets, incoming) <- fuzz.and_then({
      let has_incoming <- fuzz.and_then(fuzz.bool())
      if (has_incoming) {
        let lovelace <- fuzz.and_then(fuzz.int_between(1, 50_000_000))
        let assets <- fuzz.and_then(fuzz_assets(3) |> fuzz.map(_, assets.from_asset_list))
        let transaction_id <- fuzz.map(fuzz.bytearray_fixed(28))
        (
          assets,
          Some(Input {
            output_reference: OutputReference {
              transaction_id,
              output_index: 0
            },
            output: Output {
              address: inbox_address,
              value: assets.merge(assets.from_lovelace(lovelace), assets),
              datum: InlineDatum(owner),
              reference_script: None
            }
          })
        )
      } else {
        fuzz.constant((assets.zero, None))
      }
    })
    let (outgoing_assets, outgoing) <- fuzz.and_then({
      let has_outgoing <- fuzz.and_then(fuzz.bool())
      if (has_outgoing) {
        let _lovelace <- fuzz.and_then(fuzz.int_between(1, 50_000_000))
        let assets <- fuzz.map(fuzz_assets(3) |> fuzz.map(_, assets.from_asset_list))
        (
          assets,
          Some(Output {
            address: Address {
              payment_credential: VerificationKey(owner),
              stake_credential: None,
            },
            value: assets.merge(assets.zero, assets),
            datum: NoDatum,
            reference_script: None,
          }),
        )
      } else {
        fuzz.constant((assets.zero, None))
      }
    })
    let transaction_id <- fuzz.map(fuzz.bytearray_fixed(32))

    let account_input = Input {
      output_reference: OutputReference {
        transaction_id,
        output_index: 0
      },
      output: Output {
        address: account_address,
        value: assets.merge(base_value, outgoing_assets),
        datum: InlineDatum(Void),
        reference_script: None
      }
    }

    let account_output = Output {
      address: account_address,
      value: assets.merge(base_value, incoming_assets),
      datum: InlineDatum(Void),
      reference_script: None
    }

    let owner_inputs = when incoming is {
      Some(inbox_input) -> [account_input, inbox_input]
      _ -> [account_input]
    }
    let owner_outputs = when outgoing is {
      Some(owner_output) -> [account_output, owner_output]
      _ -> [account_output]
    }
    (list.concat(inputs, owner_inputs), list.concat(outputs, owner_outputs))
  })

  (
    inputs |> list.sort(_, fn (a: Input, b: Input) {
      bytearray.compare(a.output_reference.transaction_id, b.output_reference.transaction_id)
    }),
    outputs
  )
}

test bst_prop(assets: Dict<KeyHash, Value> via fuzz_owner_assets(4)) {
  expect _tree = owner_assets_to_tree(assets, bst.Leaf, bst.insert)
  True
}

bench bst_units(assets: Dict<KeyHash, Value> via fuzz_owner_assets) {
  let bst = owner_assets_to_tree(assets, bst.Leaf, bst.insert)
  expect list.foldl(
    dict.to_pairs(assets),
    True,
    fn (Pair(owner, assets), prev) {
      list.foldl(
        assets.flatten(assets),
        prev,
        fn ((policy_id, asset_name, quantity), prev) {
          let key = owner |> bytearray.concat(policy_id) |> bytearray.concat(asset_name)
          and{
            prev,
            bst.lookup(bst, key, bytearray.compare) == Some(quantity),
          }
        }
      )
    }
  )
}

bench radix_units(assets: Dict<KeyHash, Value> via fuzz_owner_assets) {
  let radix_tree = owner_assets_to_tree(assets, radix.empty(), radix.insert)
  expect list.foldl(
    dict.to_pairs(assets),
    True,
    fn (Pair(owner, assets), prev) {
      list.foldl(
        assets.flatten(assets),
        prev,
        fn ((policy_id, asset_name, quantity), prev) {
          let key = owner |> bytearray.concat(policy_id) |> bytearray.concat(asset_name)
          and{
            prev,
            radix.lookup(radix_tree, key) == Some(quantity)
          }
        }
      )
    }
  )
}

bench bst_sync((inputs, outputs): (List<Input>, List<Output>) via fuzz_sync) {
  let bst = list.foldl(
    inputs,
    bst.Leaf,
    fn (input, bst) {
      let payment_credential = input.output.address.payment_credential
      let owner = if payment_credential == Script(account_script) {
        expect Script(script_hash) = input.output.address.payment_credential
        expect [Pair(owner, 1)] = input.output.value |> assets.tokens(script_hash) |> dict.to_pairs()
        Some(owner)
      } else if payment_credential == Script(inbox_script) {
        expect owner: ByteArray = {
          expect InlineDatum(datum) = input.output.datum
          datum
        }
        Some(owner)
      } else {
        None
      }
      when owner is {
        Some(owner) -> {
          let (policy_id, token_name, quantity), bst <- list.foldl(input.output.value |> assets.flatten, bst)
          bst.insert(
            bst,
            owner |> bytearray.concat(policy_id) |> bytearray.concat(token_name),
            quantity,
            bytearray.compare
          )
        }
        None -> bst
      }
    }
  )
  expect list.foldl(
    outputs,
    True,
    fn (output, acc) {
      when output.datum is {
        InlineDatum(d) -> {
          expect is_account: Bool = d
          if is_account {
            expect Script(script_hash) = output.address.payment_credential
            expect [Pair(owner, 1)] = output.value |> assets.tokens(script_hash) |> dict.to_pairs()
            let (policy_id, token_name, quantity), prev <- list.foldl(output.value |> assets.flatten, acc)
            prev && Some(quantity) == bst.lookup(
              bst,
              owner |> bytearray.concat(policy_id) |> bytearray.concat(token_name),
              bytearray.compare
            )
          } else {
            acc
          }
        }
        _ -> {
          expect VerificationKey(owner) = output.address.payment_credential
          let (policy_id, token_name, quantity), prev <- list.foldl(output.value |> assets.flatten, acc)
          prev && Some(quantity) == bst.lookup(
            bst,
            owner |> bytearray.concat(policy_id) |> bytearray.concat(token_name),
            bytearray.compare
          )
        }
      }
    }
  )
  1
}

fn sync_with(
  inputs: List<Input>,
  outputs: List<Output>,
  empty: t,
  update: fn (KeyHash, Value, t) -> t
) -> (t, t) {
  let in_result = list.foldl(
    inputs,
    empty,
    fn (input, acc) {
      let payment_credential = input.output.address.payment_credential
      let owner = if payment_credential == Script(account_script) {
        expect Script(script_hash) = input.output.address.payment_credential
        expect [Pair(owner, 1)] = input.output.value |> assets.tokens(script_hash) |> dict.to_pairs()
        Some(owner)
      } else if payment_credential == Script(inbox_script) {
        expect owner: ByteArray = {
          expect InlineDatum(datum) = input.output.datum
          datum
        }
        Some(owner)
      } else {
        None
      }
      when owner is {
        Some(owner) -> update(owner, input.output.value, acc)
        None -> acc
      }
    }
  )
  let out_result = list.foldl(
    outputs,
    empty,
    fn (output, acc) {
      let payment_credential = output.address.payment_credential
      let owner = if payment_credential == Script(account_script) {
        expect Script(script_hash) = output.address.payment_credential
        expect [Pair(owner, 1)] = output.value |> assets.tokens(script_hash) |> dict.to_pairs()
        Some(owner)
      } else {
        expect VerificationKey(owner) = output.address.payment_credential
        Some(owner)
      }
      when owner is {
        Some(owner) -> update(owner, output.value, acc)
        None -> acc
      }
    }
  )
  (in_result, out_result)
}

fn radix_sync_impl((inputs, outputs): (List<Input>, List<Output>)) {
  let update = fn (old: Int, new: Int) { old + new }
  let (radix_in, radix_out) = sync_with(
    inputs,
    outputs,
    radix.empty(),
    fn (owner, value, acc) {
      let (policy_id, token_name, quantity), radix <- list.foldl(value |> assets.flatten, acc)
      radix.upsert(
        radix,
        owner |> bytearray.concat(policy_id) |> bytearray.concat(token_name),
        quantity,
        update
      )
    }
  )
  radix_in == radix_out
}

bench radix_sync((inputs, outputs): (List<Input>, List<Output>) via fuzz_sync) {
  expect radix_sync_impl((inputs, outputs))
}

bench dict_sync((inputs, outputs): (List<Input>, List<Output>) via fuzz_sync) {
  let (owner_assets_in, owner_assets_out) = sync_with(
    inputs,
    outputs,
    dict.empty,
    fn (owner, value, acc) {
      dict.union_with(
        acc,
        dict.from_pairs([Pair(owner, value)]),
        fn (_key, a, b, keep, _discard) { keep(assets.merge(a, b)) }
      )
    }
  )
  expect owner_assets_in == owner_assets_out
}

test xyz() {
  let seed = "xyzabc"
  expect None = {
    let x <- option.and_then(fuzz.int()(Seeded { seed: blake2b_224(seed), choices: "" }))
    let y <- option.and_then(fuzz.int()(x.1st))
    let z <- option.and_then(fuzz.int()(y.1st))
    let assets <- option.and_then(fuzz_owner_assets(8)(z.1st))
    let radix_tree = owner_assets_to_tree(assets.2nd, radix.empty(), radix.insert)
    let bst = owner_assets_to_tree(assets.2nd, bst.Leaf, bst.insert)

    expect list.foldl(
      dict.to_pairs(assets.2nd),
      True,
      fn (Pair(owner, assets), prev) {
        list.foldl(
          assets.flatten(assets),
          prev,
          fn ((policy_id, asset_name, quantity), prev) {
            let key = owner |> bytearray.concat(policy_id) |> bytearray.concat(asset_name)
            and{
              prev,
              bst.lookup(bst, key, bytearray.compare) == Some(quantity),
              radix.lookup(radix_tree, key) == Some(quantity)
            }
          }
        )
      }
    )
    None
  }
  True
}

test abc() {
  let seed = "xyzabc"
  expect None = {
    let x <- option.and_then(fuzz.int()(Seeded { seed: blake2b_224(seed), choices: "" }))
    let sync <- option.and_then(fuzz_sync(2)(x.1st))
    expect radix_sync_impl(sync.2nd)
    None
  }
  True
}

