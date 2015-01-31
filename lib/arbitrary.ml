open QuickCheck
open QuickCheck_gen

  let arbitrary_port = 
    arbitrary_int >>= fun p -> ret_gen (abs (p mod 65536))

  let arbitrary_ip = 
    let byte_switch is_ipv6 bytes =
      match is_ipv6 with
      | true -> Ipaddr.V6 (Ipaddr.V6.of_bytes_exn bytes) (* Ipaddr.V6.t = 4x int32 *)
      | false -> Ipaddr.V4 (Ipaddr.V4.of_bytes_raw bytes 12) (* Ipaddr.V4.t = int32 *)
    in
    arbitrary_pair arbitrary_bool (arbitrary_bytesequenceN 16) >>=
    fun (b, i) -> ret_gen (byte_switch b i)

  (* protocol really should probably be arbitrary_int, but instead
   * we'll choose randomly between 6 (tcp) and 17 (udp).  (next header in ipv6
    * is 8 bits, same for protocol in ipv4) *)
  let arbitrary_tcp_or_udp = 
    arbitrary_bool >>= fun p -> ret_gen (if p then 6 else 17)

  let qc_printer = function

    | Success -> "Randomized check passed"
    | Failure n -> Printf.sprintf "Randomized test failure after %d tests" n
    | Exhausted n -> Printf.sprintf "Random test pool exhausted after %d
    tests" n

  let arbitrary_table_entry =
    let arbitrary_ip_port = arbitrary_pair arbitrary_ip arbitrary_port in
    arbitrary_triple arbitrary_tcp_or_udp arbitrary_ip_port arbitrary_ip_port
