(* Some convenience functions to hide how ugly some packet operations are.
   This module, and others like it, might inspire some API changes in the next
   major release of mirage-tcpip. *)

let get_dst (`IPv4 (packet, _) : Nat_packet.t) = packet.Ipv4_packet.dst

let try_decompose cache ~now f packet =
  let cache', r = Nat_packet.of_ipv4_packet !cache ~now:(now ()) packet in
  cache := cache';
  match r with
  | Error e ->
    Logs.err (fun m -> m "of_ipv4_packet error %a" Nat_packet.pp_error e);
    Lwt.return_unit
  | Ok Some packet -> f packet
  | Ok None -> Lwt.return_unit
