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
  let compare = Stdlib.compare
end

module Ports = struct
  type t = (Mirage_nat.port * Mirage_nat.port) channel
  let compare = Stdlib.compare
end

module Port_cache = Lru.F.Make(Ports)(Uniform_weights(Ports))
module Id_cache = Lru.F.Make(Id)(Uniform_weights(Id))

module Storage = struct

  type defaults = {
    empty_tcp : Port_cache.t;
    empty_udp : Port_cache.t;
    empty_icmp : Id_cache.t;
  }

  type t = {
    defaults : defaults;
    tcp: Port_cache.t ref;
    udp: Port_cache.t ref;
    icmp: Id_cache.t ref;
  }

  module Subtable
      (L : sig
         type transport_channel
         module LRU : Lru.F.S with type v = transport_channel channel
         val table : t -> LRU.t ref
       end)
  = struct
    type transport_channel = L.transport_channel
    type nonrec channel = transport_channel channel

    let lookup t key =
      MProf.Trace.label "Mirage_nat_lru.lookup.read";
      let t = L.table t in
      match L.LRU.find key !t with
      | None -> Lwt.return_none
      | Some _ as r -> t := L.LRU.promote key !t; Lwt.return r

    (* cases that should result in a valid mapping:
       neither side is already mapped *)
    let insert t mappings =
      MProf.Trace.label "Mirage_nat_lru.insert";
      let t = L.table t in
      match mappings with
      | [] -> Lwt.return (Ok ())
      | m :: ms ->
        let known (src, _dst) = L.LRU.mem src !t in
        let first_known = known m in
        if List.exists (fun x -> known x <> first_known) ms then Lwt.return (Error `Overlap)
        else (
          (* TODO: this is not quite right if all mappings already exist, because it's possible that
             the lookups are part of differing pairs -- this situation is pathological, but possible *)
          let t' = List.fold_left (fun t (a, b) -> L.LRU.add a b t) !t mappings in
          t := L.LRU.trim t';
          Lwt.return_ok ()
        )

    let delete t mappings =
      let t = L.table t in
      let t' = List.fold_left (fun t m -> L.LRU.remove m t) !t mappings in
      t := t';
      Lwt.return_unit

    let pp f t = Fmt.pf f "%d/%d" (L.LRU.size !t) (L.LRU.capacity !t)
  end

  module TCP  = Subtable(struct module LRU = Port_cache let table t = t.tcp  type transport_channel = Mirage_nat.port * Mirage_nat.port end)
  module UDP  = Subtable(struct module LRU = Port_cache let table t = t.udp  type transport_channel = Mirage_nat.port * Mirage_nat.port end)
  module ICMP = Subtable(struct module LRU = Id_cache   let table t = t.icmp type transport_channel = Cstruct.uint16                    end)

  (* TODO remove Lwt.t *)
  let reset t =
    t.tcp := t.defaults.empty_tcp;
    t.udp := t.defaults.empty_udp;
    t.icmp := t.defaults.empty_icmp;
    Lwt.return ()

  let remove_connections t ip =
    let (=) a b = Ipaddr.V4.compare a b = 0 in
    let drop_connections empty table =
      Port_cache.fold (fun ((src, _, _) as k) ((src', _, (xl_port, _)) as v) (acc, ports) ->
        if ip = src then
          acc, xl_port :: ports
        else if ip = src' then
          acc, ports
        else
          Port_cache.add k v acc, ports) (empty, []) table
    in
    let tcp, freed_tcp_ports = drop_connections t.defaults.empty_tcp !(t.tcp) in
    t.tcp := tcp;
    let udp, freed_udp_ports = drop_connections t.defaults.empty_udp !(t.udp) in
    t.udp := udp;
    let icmp = Id_cache.fold (fun ((src, _, _) as k) ((src', _, _) as v) acc ->
       if ip = src || ip = src' then
         acc
       else
         Id_cache.add k v acc) t.defaults.empty_icmp !(t.icmp)
    in
    t.icmp := icmp;
    Mirage_nat.{ tcp = freed_tcp_ports ; udp = freed_udp_ports }

  let empty ~tcp_size ~udp_size ~icmp_size =
    let defaults = {
      empty_tcp = Port_cache.empty tcp_size;
      empty_udp = Port_cache.empty udp_size;
      empty_icmp = Id_cache.empty icmp_size;
    } in
    Lwt.return {
      defaults;
      tcp = ref defaults.empty_tcp;
      udp = ref defaults.empty_udp;
      icmp = ref defaults.empty_icmp;
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
