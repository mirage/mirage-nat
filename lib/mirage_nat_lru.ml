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
    mutable tcp: Port_cache.t;
    mutable udp: Port_cache.t;
    mutable icmp: Id_cache.t;
  }

  module Subtable
      (L : sig
         type transport_channel
         module LRU : Lru.F.S with type v = transport_channel channel
         val table : t -> LRU.t
         val update_table : t -> LRU.t -> unit
       end)
  = struct
    type transport_channel = L.transport_channel
    type nonrec channel = transport_channel channel

    let lookup t key =
      let table = L.table t in
      match L.LRU.find key table with
      | None -> None
      | Some _ as r -> L.update_table t (L.LRU.promote key table); r

    (* cases that should result in a valid mapping:
       neither side is already mapped *)
    let insert t mappings =
      let table = L.table t in
      match mappings with
      | [] -> Ok ()
      | m :: ms ->
        let known (src, _dst) = L.LRU.mem src table in
        let first_known = known m in
        if List.exists (fun x -> known x <> first_known) ms then Error `Overlap
        else (
          (* TODO: this is not quite right if all mappings already exist, because it's possible that
             the lookups are part of differing pairs -- this situation is pathological, but possible *)
          let table' =
            List.fold_left (fun t (a, b) -> L.LRU.add a b t) table mappings
          in
          L.update_table t (L.LRU.trim table');
          Ok ()
        )

    let delete t mappings =
      let table = L.table t in
      let table' = List.fold_left (fun t m -> L.LRU.remove m t) table mappings in
      L.update_table t table'

    let pp f t = Fmt.pf f "%d/%d" (L.LRU.size t) (L.LRU.capacity t)
  end

  module TCP  = Subtable(struct module LRU = Port_cache
      let table t = t.tcp
      let update_table t tcp = t.tcp <- tcp
      type transport_channel = Mirage_nat.port * Mirage_nat.port
    end)
  module UDP  = Subtable(struct module LRU = Port_cache
      let table t = t.udp
      let update_table t udp = t.udp <- udp
      type transport_channel = Mirage_nat.port * Mirage_nat.port
    end)
  module ICMP = Subtable(struct module LRU = Id_cache
      let table t = t.icmp
      let update_table t icmp = t.icmp <- icmp
      type transport_channel = Cstruct.uint16
    end)

  let reset t =
    t.tcp <- t.defaults.empty_tcp;
    t.udp <- t.defaults.empty_udp;
    t.icmp <- t.defaults.empty_icmp

  let remove_connections t ip =
    let (=) a b = Ipaddr.V4.compare a b = 0 in
    let rec remove pop_lru add f t_old t freed_ports =
      match pop_lru t_old with
      | None -> t, freed_ports
      | Some ((((src, _, _) as k), ((src', _, data) as v)), t_old) ->
        let t, freed_ports =
          if ip = src then
            t, f data :: freed_ports
          else if ip = src' then
            t, freed_ports
          else
            add k v t, freed_ports
        in
        remove pop_lru add f t_old t freed_ports
    in
    let tcp, freed_tcp_ports = remove Port_cache.pop_lru Port_cache.add fst (t.tcp) t.defaults.empty_tcp [] in
    t.tcp <- tcp;
    let udp, freed_udp_ports = remove Port_cache.pop_lru Port_cache.add fst (t.udp) t.defaults.empty_udp [] in
    t.udp <- udp;
    let icmp, freed_icmp_ports = remove Id_cache.pop_lru Id_cache.add (fun x -> x) (t.icmp) t.defaults.empty_icmp [] in
    t.icmp <- icmp;
    Mirage_nat.{ tcp = freed_tcp_ports ; udp = freed_udp_ports ; icmp = freed_icmp_ports }

  let empty ~tcp_size ~udp_size ~icmp_size =
    let defaults = {
      empty_tcp = Port_cache.empty tcp_size;
      empty_udp = Port_cache.empty udp_size;
      empty_icmp = Id_cache.empty icmp_size;
    } in
    {
      defaults;
      tcp = defaults.empty_tcp;
      udp = defaults.empty_udp;
      icmp = defaults.empty_icmp;
    }

  let pp_summary f t =
    Fmt.pf f "NAT{tcp:%a udp:%a icmp:%a}"
      TCP.pp t.tcp
      UDP.pp t.udp
      ICMP.pp t.icmp

  let is_port_free t protocol ~src ~dst ~src_port ~dst_port =
    not
      (match protocol with
       | `Tcp -> Port_cache.mem (src, dst, (src_port, dst_port)) t.tcp
       | `Udp -> Port_cache.mem (src, dst, (src_port, dst_port)) t.udp
       | `Icmp -> Id_cache.mem (src, dst, src_port) t.icmp)

end

include Nat_rewrite.Make(Storage)

let empty = Storage.empty

let pp_summary = Storage.pp_summary
