open Lwt.Infix

module Protocols = Mirage_protocols_lwt

module Main
    (* our unikernel is functorized over the physical, ethernet, ARP, and IPv4
       modules for the public and private interfaces, so each one shows up as
       a module argument. *)
    (Public_net: Mirage_net_lwt.S) (Private_net: Mirage_net_lwt.S)
    (Public_ethernet : Protocols.ETHERNET) (Private_ethernet : Protocols.ETHERNET)
    (Public_arpv4 : Protocols.ARP) (Private_arpv4 : Protocols.ARP)
    (Public_ipv4 : Protocols.IPV4) (Private_ipv4 : Protocols.IPV4)
    (Random : Mirage_random.C)
  = struct

  (* Use a NAT table implementation which expires entries in response
     to memory pressure.  (See mirage-nat's documentation for more
     information on what this means.) *)
  module Nat = Mirage_nat_lru

  (* configure logs, so we can use them later *)
  let log = Logs.Src.create "nat" ~doc:"NAT device"
  module Log = (val Logs.src_log log : Logs.LOG)

  (* We'll need to make routing decisions on both the public and private
     interfaces. *)
  module Public_routing = Routing.Make(Log)(Public_arpv4)
  module Private_routing = Routing.Make(Log)(Private_arpv4)

  (* the specific impls we're using show up as arguments to start. *)
  let start public_netif private_netif
            public_ethernet private_ethernet
            public_arpv4 private_arpv4
            public_ipv4 _private_ipv4 _random =

    (* if writing a packet into a given memory buffer failed,
       log the failure, pass information on how much was written
       to the underlying function (none), and continue.
       This is a convenience function for later calls to `write`. *)
    let log_write_error = function
      | Error e -> Log.debug (fun f -> f "Failed to write packet into given buffer: %a"
                                 Nat_packet.pp_error e);
        0
      | Ok n -> n
    in

    (* in order to successfully translate, we have to send the packets we've
       changed.  define some convenience functions for sending via public and
       private interfaces so we don't have to think about ARP later, when we'll 
       be trying to think hard about translations. *)
    let output_public packet =
      let gateway = Key_gen.public_ipv4_gateway () in
      let network = fst @@ Key_gen.public_ipv4 () in
      Public_routing.destination_mac network gateway public_arpv4 (Util.get_dst packet) >>= function
      | Error `Local ->
        Log.debug (fun f -> f "Could not send a packet from the public interface to the local network,\
                                as a failure occurred on the ARP layer");
        Lwt.return_unit
      | Error `Gateway ->
        Log.debug (fun f -> f "Could not send a packet from the public interface to the wider network,\
                                as a failure occurred on the ARP layer");
        Lwt.return_unit
      | Ok destination ->
        Public_ethernet.write public_ethernet destination `IPv4
          (fun b -> log_write_error @@ Nat_packet.into_cstruct packet b) >>= function
        | Error e ->
          Log.debug (fun f -> f "Failed to send packet from public interface: %a"
                        Public_ethernet.pp_error e);
          Lwt.return_unit
        | Ok () -> Lwt.return_unit
    in

    let output_private packet =
      let network = fst @@ Key_gen.private_ipv4 () in
      Private_routing.destination_mac network None private_arpv4 (Util.get_dst packet) >>= function
      | Error _ ->
        Log.debug (fun f -> f "Could not send a packet from the private interface to the local network,\
                                as a failure occurred on the ARP layer");
        Lwt.return_unit
      | Ok destination ->
        Private_ethernet.write private_ethernet destination `IPv4
          (fun b -> log_write_error @@ Nat_packet.into_cstruct packet b) >>= function
        | Error e ->
          Log.debug (fun f -> f "Failed to send packet from private interface: %a"
                        Private_ethernet.pp_error e);
          Lwt.return_unit
        | Ok () -> Lwt.return_unit
    in

    (* when we see packets on the private interface,
       we should check to see whether a translation exists for them already.
       If there is one, we would like to translate the packet and send it out
       the public interface.
       If there isn't, we should add one, then do as above.
    *)
    let rec ingest_private table packet =
      Log.debug (fun f -> f "Private interface got a packet: %a" Nat_packet.pp packet);
      Nat.translate table packet >>= function
      | Ok packet -> output_public packet
      | Error `TTL_exceeded ->
        (* TODO: if we were really keen, we'd send them an ICMP message back. *)
        (* But for now, let's just drop the packet. *)
        Log.debug (fun f -> f "TTL exceeded for a packet on the private interface");
        Lwt.return_unit
      | Error `Untranslated ->
        add_rule table packet
    and add_rule table packet =
      (* In order to add a source NAT rule, we have to come up with an unused
         source port to use for disambiguating return traffic. *)
      let public_ip = Public_ipv4.src public_ipv4 ~dst:Util.(get_dst packet) in
      (* TODO: this may generate low-numbered source ports, which may be treated
         with suspicion by other nodes on the network *)
      let port = Cstruct.BE.get_uint16 (Random.generate 2) 0 in
      Nat.add table ~now:0L packet (public_ip, port) `NAT >>= function
      | Error e ->
        Log.debug (fun f -> f "Failed to add a NAT rule: %a" Mirage_nat.pp_error e);
        Lwt.return_unit
      | Ok () -> ingest_private table packet
    in

    (* when we see packets on the public interface,
       we only want to translate them and send them out over the private
       interface if a rule already exists.
       we shouldn't make new rules from public traffic. *)
    let ingest_public table packet =
      Nat.translate table packet >>= function
      | Ok packet -> output_private packet
      | Error `TTL_exceeded ->
        Log.debug (fun f -> f "TTL exceeded for a packet on the public interface");
        Lwt.return_unit
      | Error `Untranslated ->
        Log.debug (fun f -> f
                      "Packet received on public interface for which no match exists.  BLOCKED!");
        Lwt.return_unit
    in

    (* get an empty NAT table *)
    Nat.empty ~tcp_size:1024 ~udp_size:1024 ~icmp_size:20 >>= fun table ->

    (* we need to establish listeners for the private and public interfaces *)
    (* we're interested in all traffic to the physical interface; we'd like to
       send ARP traffic to the normal ARP listener and responder,
       handle ipv4 traffic with the functions we've defined above for NATting,
       and ignore all ipv6 traffic (ipv6 has no need for NAT!). *)
    (* header_size is 14 for Ethernet networks.  If an 802.1q tag is present,
       this should instead be 18. *)
    let listen_public = Public_net.listen ~header_size:14 public_netif (
        Public_ethernet.input ~arpv4:(Public_arpv4.input public_arpv4)
                              ~ipv4:(Util.try_decompose (ingest_public table))
                              ~ipv6:(fun _ -> Lwt.return_unit)
                              public_ethernet
      ) >>= function
      | Error e -> Log.debug (fun f -> f "public interface stopped: %a"
                                 Public_net.pp_error e); Lwt.return_unit
      | Ok () -> Log.debug (fun f -> f "public interface terminated normally");
        Lwt.return_unit
    in

    (* As above, header_size is 14 for Ethernet networks.
       If an 802.1q tag is present, this should instead be 18. *)
    let listen_private = Private_net.listen ~header_size:14 private_netif (
        Private_ethernet.input ~arpv4:(Private_arpv4.input private_arpv4)
                              ~ipv4:(Util.try_decompose (ingest_private table))
                              ~ipv6:(fun _ -> Lwt.return_unit)
                              private_ethernet
      ) >>= function
      | Error e -> Log.debug (fun f -> f "private interface stopped: %a"
                                 Private_net.pp_error e); Lwt.return_unit
      | Ok () -> Log.debug (fun f -> f "private interface terminated normally");
        Lwt.return_unit
    in

    (* Notice how we haven't said anything about ICMP anywhere.  The unikernel
       doesn't know anything about it, so pinging this host on either interface
       will just be ignored -- the only way this unikernel can be easily seen,
       without sending traffic through it, is via ARP.  The `arping` command
       line utility might be useful in trying to see whether your unikernel is
       up.  *)

    (* start both listeners, and continue as long as both are working. *)
    Lwt.pick [
      listen_public;
      listen_private;
    ]
end
