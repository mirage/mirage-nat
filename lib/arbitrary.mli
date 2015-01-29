open QuickCheck_gen

val arbitrary_ip : Ipaddr.t gen
val arbitrary_port : int gen
val arbitrary_tcp_or_udp : int gen
val arbitrary_table_entry : (int * (Ipaddr.t * int) * (Ipaddr.t * int)) gen
val qc_printer : QuickCheck.testresult -> string
