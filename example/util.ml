(* Some convenience functions to hide how ugly some packet operations are.
   This module, and others like it, might inspire some API changes in the next
   major release of mirage-tcpip. *)

let ethernet_frame ~source ~destination ethertype =
  let open Ethernet_packet in
  Ethernet_packet.Marshal.make_cstruct { source; destination; ethertype }

let get_dst (`IPv4 (packet, _) : Nat_packet.t) = packet.Ipv4_packet.dst

let try_decompose f packet = match Nat_packet.of_ipv4_packet packet with
  | Error _ -> Lwt.return_unit
  | Ok packet -> f packet
