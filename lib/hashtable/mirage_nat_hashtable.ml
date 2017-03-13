(* TODO: types should be more complex and allow for entries mapping
   networks and port ranges (with logic disallowing many:many mappings), e.g.
   type One = port
   type Many = port list
   type mapping = [ One * One, One * Many, Many * One ]

   Doing this will cause us to need a real parser.
*)

type 'a channel = Ipaddr.V4.t * Ipaddr.V4.t * 'a
type 'a table = ('a channel, Mirage_nat.time * 'a channel) Hashtbl.t

module Storage = struct

  type t = {
    tcp: (Mirage_nat.port * Mirage_nat.port) table;
    udp: (Mirage_nat.port * Mirage_nat.port) table;
    icmp: Cstruct.uint16 table;
  }

  module Subtable(L : sig type transport_channel val table : t -> transport_channel table end) = struct
    type transport_channel = L.transport_channel
    type nonrec channel = transport_channel channel

    let lookup t key =
      MProf.Trace.label "Mirage_nat_hashtable.lookup.read";
      let t = L.table t in
      try Lwt.return (Some (Hashtbl.find t key))
      with Not_found -> Lwt.return_none

    (* cases that should result in a valid mapping:
       neither side is already mapped *)
    let insert t ~expiry mappings =
      MProf.Trace.label "Mirage_nat_hashtable.insert";
      let t = L.table t in
      match mappings with
      | [] -> Lwt.return (Ok ())
      | m :: ms ->
        let known (src, _dst) = Hashtbl.mem t src in
        let first_known = known m in
        if List.exists (fun x -> known x <> first_known) ms then Lwt.return (Error `Overlap)
        else (
          (* TODO: this is not quite right if all mappings already exist, because it's possible that
             the lookups are part of differing pairs -- this situation is pathological, but possible *)
          List.iter (fun (a, b) -> Hashtbl.add t a (expiry, b)) mappings;
          Lwt.return (Ok ())
        )

    let delete t mappings =
      let t = L.table t in
      List.iter (Hashtbl.remove t) mappings;
      Lwt.return_unit
  end

  module TCP  = Subtable(struct type transport_channel = Mirage_nat.port * Mirage_nat.port let table t = t.tcp end)
  module UDP  = Subtable(struct type transport_channel = Mirage_nat.port * Mirage_nat.port let table t = t.udp end)
  module ICMP = Subtable(struct type transport_channel = Cstruct.uint16 let table t = t.icmp end)

  let reset t =
    Hashtbl.reset t.tcp;
    Hashtbl.reset t.udp;
    Hashtbl.reset t.icmp;
    Lwt.return_unit

  let empty () =
    (* initial size is completely arbitrary *)
    Lwt.return {
      tcp = Hashtbl.create 21;
      udp = Hashtbl.create 21;
      icmp = Hashtbl.create 21;
    }

end

include Nat_rewrite.Make(Storage)

let empty = Storage.empty
