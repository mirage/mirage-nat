module Unix_clock = struct
  let now () = Int64.of_float (Unix.time ())
end
module Unix_time = struct
  type 'a io = 'a Lwt.t
  let sleep_ns t = Lwt_unix.sleep (Int64.to_float t /. 1e9)
end
