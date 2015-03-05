# Install OCaml and OPAM PPAs
case "$OCAML_VERSION" in
	4.01.0) ppa=avsm/ocaml41+opam12 ;;
4.02.0) ppa=avsm/ocaml42+opam12 ;;
*) echo Unknown $OCAML_VERSION; exit 1 ;;
esac
echo "yes" | sudo add-apt-repository ppa:$ppa
sudo apt-get update -qq
sudo apt-get install -qq ocaml ocaml-native-compilers camlp4-extra opam time libgmp-dev
echo OCaml version
ocaml -version
export OPAMYES=1
opam init git://github.com/ocaml/opam-repository >/dev/null 2>&1
opam repo add mirage-dev .
opam update -u
TARGETS="tcpip ounit ipaddr"
opam install ${TARGETS}
eval `opam config env`
make test
