use aiken/collection/list

pub fn and_(xs) {
  list.foldl(xs, True, &&)
}

pub fn or_(xs) {
  list.foldl(xs, False, ||)
}

pub fn id(x: t) -> t {
  x
}

pub fn const_(x: t) -> fn(t) -> t {
  fn (_) { x }
}
