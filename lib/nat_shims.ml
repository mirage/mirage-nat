(* this is temporary -- waiting on merge of nojb's pr for cstruct in ipaddr,
 * see https://github.com/mirage/ocaml-ipaddr/pull/36
 * ...we may be waiting a while
 * unfortunately tcpip/lib/ipv6.ml is in this position as well *)
module V4 = struct
  type t = Ipaddr.V4.t

  let make a b c d =
    let (~|) = Int32.of_int in
    let (&&&) x y = Int32.logand x y in
    let (|||) x y = Int32.logor x y in
    let (<|<) x y = Int32.shift_left x y in
    let (<!)  x y = (x &&& 0xFF_l) <|< y in

    ((~| a <! 24) ||| (~| b <! 16)) ||| ((~| c <! 8) ||| (~| d <! 0))

  (* Cstruct conversion *)
  let of_cstruct_raw cs o =
    make
      (Char.code (Cstruct.get_char cs (0 + o)))
      (Char.code (Cstruct.get_char cs (1 + o)))
      (Char.code (Cstruct.get_char cs (2 + o)))
      (Char.code (Cstruct.get_char cs (3 + o)))

  let of_cstruct_exn cs =
    let len = Cstruct.len cs in
    if len < 4 then raise (Invalid_argument (Cstruct.to_string cs));
    if len > 4 then raise (Invalid_argument (Cstruct.to_string cs));
    of_cstruct_raw cs 0

  let to_cstruct_raw i cs o =
    let (>|>) x y = Int32.shift_right_logical x y in
    let (&&&) x y = Int32.logand x y in
    let (>!)  x y = (x >|> y) &&& 0xFF_l in
    Cstruct.set_char cs (0 + o) (Char.chr (Int32.to_int (i >! 24)));
    Cstruct.set_char cs (1 + o) (Char.chr (Int32.to_int (i >! 16)));
    Cstruct.set_char cs (2 + o) (Char.chr (Int32.to_int (i >!  8)));
    Cstruct.set_char cs (3 + o) (Char.chr (Int32.to_int (i >!  0)))

  let to_cstruct i =
    let cs = Cstruct.create 4 in
    to_cstruct_raw i cs 0;
    cs
end

module V6 = struct
  let of_cstruct_raw cs o =
    let hihi = V4.of_cstruct_raw cs (o + 0) in
    let hilo = V4.of_cstruct_raw cs (o + 4) in
    let lohi = V4.of_cstruct_raw cs (o + 8) in
    let lolo = V4.of_cstruct_raw cs (o + 12) in
    Ipaddr.V6.of_int32 (hihi, hilo, lohi, lolo)

  let of_cstruct_exn cs =
    let len = Cstruct.len cs in
    if len > 16 then raise (Invalid_argument (Cstruct.to_string cs));
    if len < 16 then raise (Invalid_argument (Cstruct.to_string cs));
    of_cstruct_raw cs 0

  let to_cstruct_raw (a,b,c,d) cs o =
    V4.to_cstruct_raw a cs (0+0);
    V4.to_cstruct_raw b cs (0+4);
    V4.to_cstruct_raw c cs (0+8);
    V4.to_cstruct_raw d cs (0+12)

  let to_cstruct i =
    let cs = Cstruct.create 16 in
    to_cstruct_raw i cs 0;
    cs
end
