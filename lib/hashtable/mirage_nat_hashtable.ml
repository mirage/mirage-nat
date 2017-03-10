(* TODO: types should be more complex and allow for entries mapping
   networks and port ranges (with logic disallowing many:many mappings), e.g.
   type One = port
   type Many = port list
   type mapping = [ One * One, One * Many, Many * One ]

   Doing this will cause us to need a real parser.
*)
open Mirage_nat

module Storage = struct

  type t = {
    tcp: ((endpoint * endpoint), (time * (endpoint * endpoint))) Hashtbl.t;
    udp: ((endpoint * endpoint), (time * (endpoint * endpoint))) Hashtbl.t;
    icmp: ((Ipaddr.t * Ipaddr.t * Cstruct.uint16), (time * (Ipaddr.t * Ipaddr.t * Cstruct.uint16))) Hashtbl.t;
  }

  module Subtable(L : sig type channel val table : t -> (channel, time * channel) Hashtbl.t end) = struct
    type channel = L.channel

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
          List.iter (fun (a, b) -> Hashtbl.add t a (expiry, b)) mappings;
          Lwt.return (Ok ())
        )

    let delete t mappings =
      let t = L.table t in
      List.iter (Hashtbl.remove t) mappings;
      Lwt.return_unit
  end

  module TCP  = Subtable(struct type channel = endpoint * endpoint let table t = t.tcp end)
  module UDP  = Subtable(struct type channel = endpoint * endpoint let table t = t.udp end)
  module ICMP = Subtable(struct type channel = Ipaddr.t * Ipaddr.t * Cstruct.uint16 let table t = t.icmp end)

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
