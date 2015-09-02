(* TODO: types should be more complex and allow for entries mapping
   networks and port ranges (with logic disallowing many:many mappings), e.g.
   type One = port
   type Many = port list
   type mapping = [ One * One, One * Many, Many * One ]

   Doing this will cause us to need a real parser.
*)
open Nat_types

type mode =
  | Redirect
  | Nat

let (>>=) = Lwt.bind

module type S = sig
  module I : Irmin.S
  type t

  val lookup : t -> Nat_table.Key.protocol ->
    source:Nat_table.Endpoint.t ->
    destination:Nat_table.Endpoint.t ->
    mapping option Lwt.t

  val insert : t -> int -> Nat_table.Key.protocol -> translation -> t option Lwt.t

  val delete : t -> Nat_table.Key.protocol ->
    internal_lookup:Nat_table.Endpoint.mapping ->
    external_lookup:Nat_table.Endpoint.mapping -> t Lwt.t

  val empty : Irmin.config -> t Lwt.t
end

module type CLOCK = sig
  val now : unit -> int64
end

module type TIME = sig
  val sleep : float -> unit Lwt.t
end

module Irmin_store : sig 
  module Path : Irmin.Path.S with type step = Nat_table.Key.t
  include Irmin.Contents.S with module Path := Path and type t = Nat_table.Entry.t
end = struct

  let default_hash = Hashtbl.hash

  module Path : sig
    type step = Nat_table.Key.t
    include Irmin.Path.S with type step := step
  end = struct
    module Key = Nat_table.Key
    module Step : sig
      include Inds_types.KEY with type t := Key.t
      include Irmin.Path.STEP with type t = Key.t
    end = struct
      include Key
      let of_hum str =
        match Key.of_string str with
        | None -> raise (Invalid_argument "Failure deserializing a path element")
        | Some k -> k
      let to_hum = Key.to_string
      let hash = default_hash
      let equal x y = (compare x y = 0)

      let write t buf =
        let out = to_hum t in
        Cstruct.blit_from_string out 0 buf 0 (String.length out);
        buf

      let read buf =
        match Key.of_string (Mstruct.to_string buf) with
        | Some t -> t
        | None -> raise (Invalid_argument "Unreasable key presented in path")

      let size_of t = String.length (to_string t)
    end
    type step = Key.t
    type t = step option

    let of_hum = function
      | "" -> None
      | str -> Key.of_string str

    let to_hum = function
      | None -> ""
      | Some t -> Key.to_string t

    let write t buf =
      let out = to_hum t in
      Cstruct.blit_from_string out 0 buf 0 (String.length out);
      buf
    let read buf = Key.of_string (Mstruct.to_string buf)

    let to_json = Ezjsonm.option Key.to_json
    let of_json value = Ezjsonm.get_option Key.of_json value

    let size_of k = String.length (to_hum k)

    let compare x y = match (x, y) with
      | None, None -> 0
      | None, Some t -> 1
      | Some t, None -> -1
      | Some x, Some y -> Key.compare x y

    let equal x y = (compare x y = 0)

    let hash = default_hash

    let empty = None
    let create = function
      | [] -> None
      | step::_ -> Some step

    let is_empty = function
      | None -> true
      | Some _ -> false

    (* Some > None, earlier entries > later *) 
    let cons step _ = Some step

    (* appending to the end of a path that already had an entry does nothing *)
    let rcons t step = match t with
      | None -> Some step
      | Some t -> Some t

    let decons = function
      | Some t -> Some (t, None)
      | None -> None

    let rdecons = function
      | Some t -> Some (None, t)
      | None -> None

    let map t fn = match t with
      | None -> []
      | Some step -> [ fn step ]

  end

  module Ops = struct
    include Nat_table.Entry

    let write t buf =
      let out = to_string t in
      Cstruct.blit_from_string out 0 buf 0 (String.length out);
      buf
    let read buf = match of_string (Mstruct.to_string buf) with
      | None -> raise (Invalid_argument "unparseable entry")
      | Some t -> t

    let hash = default_hash
  end

  include Ops (* Ops is only a submodule so it can be passed to
                 Irmin.Merge.option *)

  let merge _path ~(old : Nat_table.Entry.t Irmin.Merge.promise) t1 t2 =
    let winner =
      match compare t1 t2 with
      | n when n <= 0 -> t1
      | n -> t2
    in
    Irmin.Merge.OP.ok winner

  let merge path = Irmin.Merge.option (module Ops) (merge path)

end

module Make(Backend: Irmin.S_MAKER)(Clock: CLOCK)(Time: TIME) = struct

  (* module T =
     Inds_table.Make(Nat_table.Key)(Nat_table.Entry)(Irmin.Path.String_list) *)
  module T = Irmin_store
  module I = Irmin.Basic (Backend)(T)

  let owner = "friendly natbot"

  type t = {
    config: Irmin.config;
    store: (string -> I.t);
  }

  let expired time = (Clock.now () |> Int64.to_int) > time
  let task () = Irmin.Task.create ~date:(Clock.now ()) ~owner
  
  let rec tick t () =
    MProf.Trace.label "Nat_lookup.tick";
    (* only do expiration for UDP, since we intend to do something state-based
       for TCP *)
    let expiry_check_interval = 6. in
    I.head (t.store "Nat_lookup.tick: starting expiry") >>= function
    | None -> Time.sleep expiry_check_interval >>= tick t (* nothing to expire! *)
    | Some head ->
      I.of_head t.config (task ()) head >>= fun our_br ->
      let now = Clock.now () |> Int64.to_int in
      let unwrap (Nat_table.Entry.Confirmed (time, entry)) = Lwt.return time in
      let expire key value_thread =
        value_thread >>= unwrap >>= fun time ->
        if time <= now then
          I.remove (t.store "Nat_lookup.tick: removing expired UDP entry") key 
        else
          Lwt.return_unit
      in
      I.iter (our_br "Nat_lookup.tick: scan for expired entries") expire >>= fun () ->
      I.merge_exn "merge expiry branch" our_br ~into:t.store >>= fun () ->
      Time.sleep expiry_check_interval >>= tick t

  let empty config =
    I.create config (task ()) >>= fun store ->
    let t = {
      config;
      store;
    } in
    Lwt.async (tick t);
    Lwt.return t

  let store_of_t t = t.store "read for store_of_t"

  let make_key proto (src, dst) : Nat_table.Key.t = (proto, src, dst)
  let make_path key = Irmin_store.Path.create [ key ]

  let lookup t proto ~source ~destination =
    MProf.Trace.label "Nat_lookup.lookup.read";
    let path = make_key proto (source, destination) |> make_path in
    I.read (t.store "read for lookup") path >>= function
    | None -> Lwt.return None
    | Some (Confirmed (time, entry)) ->
      if expired time then Lwt.return None else Lwt.return (Some entry)

  (* cases that should result in a valid mapping:
     neither side is already mapped *)
  let insert t expiry_interval proto mappings =
    MProf.Trace.label "Nat_lookup.insert";
    let expiration = (Clock.now () |> Int64.to_int) + expiry_interval in
    let check t proto endpoint =
      I.mem (t "insert: dup/overlap check") (make_path (make_key proto endpoint))
    in
    let get_branch () =
      I.head (t.store "insert: get temp branch") >>= function
      | Some head -> I.of_head t.config (task ()) head
      | None -> I.empty t.config (task ())
    in
    get_branch () >>= fun branch ->
    check branch proto mappings.internal_lookup >>= fun internal_mem ->
    check branch proto mappings.external_lookup >>= fun external_mem ->
    match internal_mem, external_mem with
    | true, true (* TODO: this is not quite right, because it's possible that
                        the lookups are part of differing pairs. *)
    | false, false ->
      let internal_path = make_path (make_key proto mappings.internal_lookup) in
      let external_path = make_path (make_key proto mappings.external_lookup) in
      I.update (branch "insert: add internal entry") internal_path
        (Nat_table.Entry.Confirmed (expiration, mappings.internal_mapping))
      >>= fun () ->
      I.update (branch "insert: add external entry") external_path
        (Nat_table.Entry.Confirmed (expiration, mappings.external_mapping))
      >>= fun () ->
      I.merge_exn "insert: merging new entries" branch ~into:t.store >>= fun () ->
      Lwt.return (Some t)
    | _, _ -> Lwt.return None

  let delete t proto ~internal_lookup ~external_lookup =
    MProf.Trace.label "Nat_lookup.delete";
    I.head (t.store "delete: get temp branch") >>= function
    | None -> Lwt.return t (* nothing in there to delete *)
    | Some head ->
      I.of_head t.config (task ()) head >>= fun branch ->
      I.remove (t.store "delete: remove internal entry")
        (make_path (make_key proto internal_lookup)) >>= fun () ->
      I.remove (t.store "delete: remove external entry")
        (make_path (make_key proto external_lookup)) >>= fun () ->
      I.merge_exn "delete: removing entries" branch ~into:t.store >>= fun () ->
      Lwt.return t

end
