#!/bin/bash -x

run_test() {
  DIR=$1
  pushd $DIR
  cargo test
  popd
}

run_test client/authority-discovery/
run_test client/basic-authorship
run_test client/block-builder/
run_test client/consensus/babe/
run_test client/consensus/beefy/
run_test client/consensus/grandpa/
run_test client/network
run_test client/network/bitswap/
run_test client/network/test
run_test client/offchain
run_test client/rpc
run_test client/rpc-spec-v2/
run_test client/service/test
run_test client/transaction-pool
run_test client/transaction-pool/tests
run_test primitives/trie
run_test primitives/api/test
run_test primitives/runtime
run_test test-utils/runtime
run_test test-utils/runtime/client
run_test test-utils/runtime/transaction-pool

# client/authority-discovery/src/worker
# client/basic-authorship
# client/block-builder
# client/consensus/babe
# client/consensus/beefy
# client/consensus/grandpa
# client/network/bitswap
# client/network/test
# client/offchain
# client/rpc-spec-v2
# client/rpc/src/author
# client/rpc/src/dev
# client/rpc/src/state
# client/service/src
# client/service/test/src/client
# client/transaction-pool/benches
# client/transaction-pool/src
# client/transaction-pool/src/graph
# client/transaction-pool/tests
# frame/executive/src
# primitives/api/test/tests
# primitives/consensus/grandpa/src
# primitives/runtime/src/generic
# primitives/trie
# primitives/trie/src
# primitives/trie/src/cache
# test-utils/client
# test-utils/runtime
# test-utils/runtime/client
# test-utils/runtime/client/src
# test-utils/runtime/src
# test-utils/runtime/transaction-pool/src
# utils/frame/rpc/system/src

