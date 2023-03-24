#!/bin/bash -x

pushd client/basic-authorship
cargo test
popd

pushd test-utils/runtime
cargo test
popd

pushd primitives/runtime
cargo test
popd

pushd client/transaction-pool
cargo test
popd

pushd client/offchain
cargo test
popd

pushd client/network
cargo test
popd

pushd client/network/bitswap/
cargo test
popd

pushd client/network/test
cargo test
popd

pushd client/authority-discovery/
cargo test
popd

pushd client/service/test
cargo test
popd

pushd client/consensus/grandpa/
cargo test
popd

pushd client/consensus/babe/
cargo test
popd

pushd primitives/api/test
cargo test
popd
