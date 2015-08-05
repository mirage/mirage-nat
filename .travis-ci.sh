# default tests

wget https://raw.githubusercontent.com/ocaml/ocaml-travisci-skeleton/master/.travis-opam.sh
bash -ex .travis-opam.sh

export OPAMYES=1
eval `opam config env`

./configure
ocaml setup.ml -configure --enable-test
make test
