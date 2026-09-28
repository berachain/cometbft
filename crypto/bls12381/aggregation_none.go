//go:build !bls12381

package bls12381

import (
	"errors"
)

// ErrAggregation is returned when aggregation fails.
var ErrAggregation = errors.New("bls12381: failed to aggregate signatures")

// AggregateSignatures aggregates the given compressed signatures.
//
// It returns ErrDisabled when built without the `bls12381` build tag.
func AggregateSignatures([][]byte) ([]byte, error) {
	return nil, ErrDisabled
}

// VerifyAggregateSignature verifies the given compressed aggregate signature.
//
// It returns false when built without the `bls12381` build tag.
func VerifyAggregateSignature([]byte, []*PubKey, []byte) bool {
	return false
}
