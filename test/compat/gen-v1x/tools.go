//go:build tools

// This file only exists so that `go mod tidy` records the dependencies of the
// bera-v1.x node binary in go.sum. That lets the compatibility scripts build a
// bera-v1.x `cometbft` binary straight from the module cache, without a
// bera-v1.x checkout:
//
//	cd test/compat/gen-v1x && go build -o cometbft-v1x github.com/cometbft/cometbft/cmd/cometbft
package main

import (
	_ "github.com/cometbft/cometbft/cmd/cometbft/commands"
)
