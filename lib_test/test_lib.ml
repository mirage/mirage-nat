module Unix_clock = struct
  let now () = Int64.of_float (Unix.time ())
end
module Unix_time = struct
  let sleep = Lwt_unix.sleep
end

module N = Nat_lookup.Make(Irmin_mem.Make)(Unix_clock)(Unix_time)
