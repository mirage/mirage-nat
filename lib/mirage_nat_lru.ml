(* TODO: types should be more complex and allow for entries mapping
   networks and port ranges (with logic disallowing many:many mappings), e.g.
   type One = port
   type Many = port list
   type mapping = [ One * One, One * Many, Many * One ]

   Doing this will cause us to need a real parser.
*)

type 'a channel = Ipaddr.V4.t * Ipaddr.V4.t * 'a

module Uniform_weights(T : sig type t end) = struct
  type t = T.t
  let weight _ = 1
end

module Id = struct
  type t = Cstruct.uint16 channel
  let equal = (=)
  let hash = Hashtbl.seeded_hash
end

module Ports = struct
  type t = (Mirage_nat.port * Mirage_nat.port) channel
  let equal = (=)
  let hash = Hashtbl.seeded_hash
end

module Port_cache = Lru.M.MakeSeeded(Ports)(Uniform_weights(Ports))
module Id_cache = Lru.M.MakeSeeded(Id)(Uniform_weights(Id))

module Storage = struct

  type defaults = {
    empty_tcp : unit -> Port_cache.t;
    empty_udp : unit -> Port_cache.t;
    empty_icmp : unit -> Id_cache.t;
  }

  type t = {
    defaults : defaults;
    mutable tcp: Port_cache.t;
    mutable udp: Port_cache.t;
    mutable icmp: Id_cache.t;
  }

  module Subtable
      (L : sig
         type transport_channel
         module LRU : Lru.M.S with type v = transport_channel channel
         val table : t -> LRU.t
       end)
  = struct
    type transport_channel = L.transport_channel
    type nonrec channel = transport_channel channel

    let lookup t key =
      MProf.Trace.label "Mirage_nat_hashtable.lookup.read";
      let t = L.table t in
      match L.LRU.find key t with
      | None -> Lwt.return_none
      | Some _ as r -> L.LRU.promote key t; Lwt.return r

    (* cases that should result in a valid mapping:
       neither side is already mapped *)
    let insert t mappings =
      MProf.Trace.label "Mirage_nat_hashtable.insert";
      let t = L.table t in
      match mappings with
      | [] -> Lwt.return (Ok ())
      | m :: ms ->
        let known (src, _dst) = L.LRU.mem src t in
        let first_known = known m in
        if List.exists (fun x -> known x <> first_known) ms then Lwt.return (Error `Overlap)
        else (
          (* TODO: this is not quite right if all mappings already exist, because it's possible that
             the lookups are part of differing pairs -- this situation is pathological, but possible *)
          mappings |> List.iter L.LRU.(fun (a, b) -> add a b t; trim t);
          Lwt.return_ok ()
        )

    let delete t mappings =
      let t = L.table t in
      mappings |> List.iter (fun m -> L.LRU.remove m t);
      Lwt.return_unit

    let pp f t = Fmt.pf f "%d/%d" (L.LRU.size t) (L.LRU.capacity t)
  end

  module TCP  = Subtable(struct module LRU = Port_cache let table t = t.tcp  type transport_channel = Mirage_nat.port * Mirage_nat.port end)
  module UDP  = Subtable(struct module LRU = Port_cache let table t = t.udp  type transport_channel = Mirage_nat.port * Mirage_nat.port end)
  module ICMP = Subtable(struct module LRU = Id_cache   let table t = t.icmp type transport_channel = Cstruct.uint16                    end)

  let reset t =
    t.tcp <- t.defaults.empty_tcp ();
    t.udp <- t.defaults.empty_udp ();
    t.icmp <- t.defaults.empty_icmp ();
    Lwt.return ()

  let empty ~tcp_size ~udp_size ~icmp_size =
    let defaults = {
      empty_tcp = (fun () -> Port_cache.create ~random:false tcp_size);
      empty_udp = (fun () -> Port_cache.create ~random:false udp_size);
      empty_icmp = (fun () -> Id_cache.create ~random:false icmp_size);
    } in
    Lwt.return {
      defaults;
      tcp = defaults.empty_tcp ();
      udp = defaults.empty_udp ();
      icmp = defaults.empty_icmp ();
    }

  let pp_summary f t =
    Fmt.pf f "NAT{tcp:%a udp:%a icmp:%a}"
      TCP.pp t.tcp
      UDP.pp t.udp
      ICMP.pp t.icmp

end

include Nat_rewrite.Make(Storage)

let empty = Storage.empty

let pp_summary = Storage.pp_summary
