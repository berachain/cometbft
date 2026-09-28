//go:build bls12381

package types

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto/bls12381"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

// blsPrecommits returns a precommit vote set at height 1, round 0 over n BLS
// validators of equal power, and a func that makes validator i vote for id.
func blsPrecommits(t *testing.T, n int) (*VoteSet, *ValidatorSet, func(i int32, id BlockID)) {
	t.Helper()
	vals := make([]*Validator, n)
	pvs := make([]PrivValidator, n)
	for i := range vals {
		pk, err := bls12381.GenPrivKey()
		require.NoError(t, err)
		pvs[i] = NewMockPVWithParams(pk, false, false)
		vals[i] = NewValidator(pk.PubKey(), 1)
	}
	sort.Sort(PrivValidatorsByAddress(pvs))
	valSet := NewValidatorSet(vals)
	voteSet := NewVoteSet("test_chain_id", 1, 0, cmtproto.PrecommitType, valSet)
	vote := func(i int32, id BlockID) {
		addr := valSet.Validators[i].Address
		_, err := signAddVote(pvs[i], &Vote{ValidatorAddress: addr, ValidatorIndex: i, Height: 1, Type: cmtproto.PrecommitType, BlockID: id}, voteSet)
		require.NoError(t, err)
	}
	return voteSet, valSet, vote
}

// MakeBLSCommit aggregates the votes for the +2/3 block and the nil votes
// separately, marks votes for another block absent, and panics without +2/3.
func TestVoteSet_MakeBLSCommit(t *testing.T) {
	voteSet, valSet, vote := blsPrecommits(t, 10)
	blockID := randBlockID()
	for i := int32(0); i < 6; i++ {
		vote(i, blockID)
	}
	assert.Panics(t, func() { voteSet.MakeBLSCommit() }, "no +2/3 majority yet")

	vote(6, randBlockID()) // another block, left out of the aggregate
	vote(7, blockID)
	vote(8, BlockID{}) // nil
	commit := voteSet.MakeBLSCommit()
	require.NoError(t, commit.ValidateBasic())

	a, aa := BlockIDFlagAggCommit, BlockIDFlagAggCommitAbsent
	want := []BlockIDFlag{a, aa, aa, aa, aa, aa, BlockIDFlagAbsent, aa, BlockIDFlagAggNil, BlockIDFlagAbsent}
	for i, sig := range commit.ExtendedSignatures {
		assert.Equal(t, want[i], sig.BlockIDFlag, "index %d", i)
	}
	require.NoError(t, valSet.VerifyCommit("test_chain_id", blockID, 1, commit.ToCommit()))
}

// Swapping validator addresses in an aggregated commit keeps the aggregate
// signature valid (sign bytes exclude the address), so every verify path
// must check the address against the validator set.
func TestValidatorSet_VerifyCommit_AggregatedCommitAddressMismatch(t *testing.T) {
	voteSet, valSet, vote := blsPrecommits(t, 4)
	blockID := randBlockID()
	for i := int32(0); i < 4; i++ {
		vote(i, blockID)
	}
	commit := voteSet.MakeBLSCommit().ToCommit()
	require.NoError(t, valSet.VerifyCommit("test_chain_id", blockID, 1, commit))

	sigs := commit.Signatures
	sigs[0].ValidatorAddress, sigs[1].ValidatorAddress = sigs[1].ValidatorAddress, sigs[0].ValidatorAddress
	for name, verify := range map[string]func(string, BlockID, int64, *Commit) error{
		"VerifyCommit":                   valSet.VerifyCommit,
		"VerifyCommitLight":              valSet.VerifyCommitLight,
		"VerifyCommitLightAllSignatures": valSet.VerifyCommitLightAllSignatures,
	} {
		assert.ErrorContains(t, verify("test_chain_id", blockID, 1, commit), "validator address mismatch", name)
	}
}
