//go:build bls12381

package consensus

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto/bls12381"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/types"
)

// The proposer decides whether to aggregate LastCommit from the set that
// signed it (LastValidators), not the set of the new height. Here height 1 was
// signed by a set with an ed25519 validator and height 2's set is all BLS, so
// the votes must not be aggregated (MakeBLSCommit would panic on them).
func TestCreateProposalBlockAggregatesByLastValidators(t *testing.T) {
	cp := blsConsensusParams()
	cp.Validator.PubKeyTypes = []string{bls12381.KeyType, ed25519.KeyType}
	genDoc, blsPVs := blsGenesisDoc(1, 10, cp)
	edPV := types.NewMockPV()
	edPub, err := edPV.GetPubKey()
	require.NoError(t, err)
	genDoc.Validators = append(genDoc.Validators, types.GenesisValidator{PubKey: edPub, Power: 10})
	state, err := sm.MakeGenesisState(genDoc)
	require.NoError(t, err)
	cs := newState(state, blsPVs[0], newKVStore()) // stores the mixed set for height 1

	// Both validators precommit block 1.
	blockID := types.BlockID{Hash: tmhash.Sum([]byte("b1")), PartSetHeader: types.PartSetHeader{Total: 1, Hash: tmhash.Sum([]byte("p1"))}}
	lastCommit := types.NewVoteSet(state.ChainID, 1, 0, cmtproto.PrecommitType, state.Validators)
	for _, pv := range []types.PrivValidator{blsPVs[0], edPV} {
		pub, err := pv.GetPubKey()
		require.NoError(t, err)
		idx, _ := state.Validators.GetByAddress(pub.Address())
		vs := newValidatorStub(pv, idx)
		vs.Height = 1
		_, err = lastCommit.AddVote(signVote(vs, cmtproto.PrecommitType, blockID.Hash, blockID.PartSetHeader, false))
		require.NoError(t, err)
	}

	// Height 2: only the BLS validator is left.
	_, blsVal := state.Validators.GetByAddress(genDoc.Validators[0].PubKey.Address())
	blsOnly := types.NewValidatorSet([]*types.Validator{blsVal.Copy()})
	cs.state.LastBlockHeight, cs.state.LastBlockID = 1, blockID
	cs.state.LastValidators, cs.state.Validators, cs.state.NextValidators = state.Validators, blsOnly, blsOnly
	cs.Height, cs.LastCommit = 2, lastCommit

	block, err := cs.createProposalBlock(context.Background())
	require.NoError(t, err)
	require.False(t, block.LastCommit.HasAggregatedSignature())
}
