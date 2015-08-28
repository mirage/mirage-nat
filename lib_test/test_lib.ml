module Unix_clock = struct
  let now () = Int64.of_float (Unix.time ())
end
module Unix_time = struct
  let sleep = Lwt_unix.sleep
end
