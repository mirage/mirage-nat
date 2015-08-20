type direction = | Source | Destination

type protocol = | Udp | Tcp
type port = Cstruct.uint16
type endpoint = Nat_table.Endpoint.t
type mapping = (endpoint * endpoint)

type translation = {
  internal_lookup: mapping;
  external_lookup: mapping;
  internal_mapping: mapping;
  external_mapping: mapping
}

type mode =
  | Redirect
  | Nat
