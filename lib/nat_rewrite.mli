module Make(Table : Mirage_nat.Lookup) : Mirage_nat.S with type t = Table.t
