open Mirage

(* we need two network interfaces: a public side and a private side *)
(* a bit of magic: currently, multiple networks only work on Unix and Xen
   backends, so we can get away with this indexes-as-numbers-as-strings
   silliness.
   See https://github.com/mirage/mirage/issues/645 *)
let public_netif = netif ~group:"public" "0"
let private_netif = netif ~group:"private" "1"

(* build ethernet interfaces on top of those network interfaces *)
let public_ethernet = etif public_netif
let private_ethernet = etif private_netif

(* use the functional address resolution protocol *)
let public_arpv4 = arp public_ethernet
let private_arpv4 = arp private_ethernet

(* finally, use statically configured (at build or runtime) ipv4 addresses.
   (you might want to use dhcp to configure the address on the public interface.
     this is possible, but the code is a bit too convoluted for a good example.
     for now, we'll use statically configured addresses on both interfaces. *)

let public_ipv4 = create_ipv4 ~group:"public" public_ethernet public_arpv4
let private_ipv4 = create_ipv4 ~group:"private" private_ethernet private_arpv4

let packages = [
  package "mirage-nat";
  package ~min:"2.0.0" "mirage-protocols-lwt";
  package ~min:"2.0.0" "mirage-protocols";
]

(* our unikernel needs to know about physical network, ethernet, arp, and ipv4
   modules for each interface. Even though these modules will be the same for
   both interfaces in our case, we have to pass them separately. *)
let main = foreign "Unikernel.Main" ~packages (network  @-> network  @->
                                               ethernet @-> ethernet @->
                                               arpv4    @-> arpv4    @->
                                               ipv4     @-> ipv4     @->
                                               random   @-> job)

(* we need to pass each of the network-related impls we've made to the
   unikernel, so that it can start the appropriate listeners. *)
let () = register "simple-nat" [ main
                                 $ public_netif    $ private_netif
                                 $ public_ethernet $ private_ethernet
                                 $ public_arpv4    $ private_arpv4
                                 $ public_ipv4     $ private_ipv4
                                 $ default_random
                               ]
