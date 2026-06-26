//go:build bls12381

package consensus

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/abci/example/kvstore"
	"github.com/cometbft/cometbft/crypto/bls12381"
	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/types"
	cmttime "github.com/cometbft/cometbft/types/time"
)

// blsConsensusParamsWithSynchrony returns BLS/PBTS consensus params with tight
// synchrony bounds, so the timeliness window is small enough that an
// intentionally-skewed proposal timestamp lands clearly out of window.
func blsConsensusParamsWithSynchrony(precision, msgDelay time.Duration) *types.ConsensusParams {
	c := blsConsensusParams()
	c.Synchrony = types.SynchronyParams{
		Precision:    precision,
		MessageDelay: msgDelay,
	}
	return c
}

// blsConsensusState builds a single observed consensus State plus validator
// stubs, all using bls12_381 keys with PBTS enabled. The observed State is
// privVals[0]; the returned stubs cover ALL validators (index 0 is the observed
// validator itself), mirroring randState's contract so callers can drive the
// network by hand.
func blsConsensusState(t *testing.T, nValidators int, consensusParams *types.ConsensusParams) (*State, []*validatorStub) {
	t.Helper()
	genDoc, privVals := blsGenesisDoc(nValidators, 10, consensusParams)
	state, err := sm.MakeGenesisState(genDoc)
	require.NoError(t, err)

	thisConfig := ResetConfig("blsConsensusState")
	t.Cleanup(func() { _ = os.RemoveAll(thisConfig.RootDir) })

	app := kvstore.NewInMemoryApplication()
	cs := newStateWithConfig(thisConfig, state, privVals[0], app)
	cs.SetTimeoutTicker(newMockTickerFunc(true)())

	vss := make([]*validatorStub, nValidators)
	for i := 0; i < nValidators; i++ {
		vss[i] = newValidatorStub(privVals[i], int32(i))
	}
	return cs, vss
}

// proposerStubForRound returns the validator stub whose privval is the proposer
// for the given round in cs's validator set, along with its index. It mirrors
// the increment that enterNewRound applies (IncrementProposerPriority by
// round-cs.Round on the live round-state valset) so the chosen proposer matches
// the one cs will verify the proposal signature against.
func proposerStubForRound(cs *State, vss []*validatorStub, round int32) (*validatorStub, int) {
	base := cs.Validators.Copy()
	if cs.Round < round {
		base.IncrementProposerPriority(round - cs.Round)
	}
	propAddr := base.GetProposer().Address
	for i, vs := range vss {
		pub, err := vs.GetPubKey()
		if err != nil {
			continue
		}
		if pub.Address().String() == propAddr.String() {
			return vs, i
		}
	}
	return nil, -1
}

// TestAggregationPBTSRejectsUntimelyProposal proves the PBTS timeliness gate
// actually rejects: in a BLS+PBTS network, when the proposer delivers a block
// whose timestamp is far outside the synchrony window relative to the receiver's
// clock, the observed validator prevotes NIL rather than for the block. A
// control case with an in-window timestamp prevotes for the block, proving the
// gate is selective and not simply always-nil.
func TestAggregationPBTSRejectsUntimelyProposal(t *testing.T) {
	testCases := []struct {
		name string
		// offset applied to BOTH the proposed block time and the proposal
		// timestamp, relative to "now" (the receiver's clock at prevote time).
		// Positive = future, negative = past.
		tsOffset      time.Duration
		expectNilVote bool
	}{
		{
			name:          "timely_proposal_prevotes_for_block",
			tsOffset:      0, // proposal time == now, clearly inside window
			expectNilVote: false,
		},
		{
			name:          "future_proposal_prevotes_nil",
			tsOffset:      1 * time.Hour, // way beyond MessageDelay+Precision
			expectNilVote: true,
		},
		{
			name:          "past_proposal_prevotes_nil",
			tsOffset:      -1 * time.Hour, // way before now-Precision
			expectNilVote: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			// Tight synchrony: 10ms precision, 50ms message delay. The 1h skew in
			// the negative cases dwarfs this window; the 0 offset sits inside it.
			cp := blsConsensusParamsWithSynchrony(10*time.Millisecond, 50*time.Millisecond)
			cs, vss := blsConsensusState(t, 4, cp)

			// Sanity: the aggregation path is in play (all BLS keys).
			require.True(t, cs.state.Validators.AllKeysHaveSameType())
			pk0, err := vss[0].GetPubKey()
			require.NoError(t, err)
			require.Equal(t, bls12381.KeyType, pk0.Type())

			height, round := cs.Height, cs.Round

			proposalCh := subscribe(cs.eventBus, types.EventQueryCompleteProposal)
			voteCh := subscribe(cs.eventBus, types.EventQueryVote)

			// Build the proposal block from the observed state, then have a
			// DIFFERENT validator (a stub) act as proposer so the observed
			// validator must evaluate timeliness on a received proposal rather
			// than proposing itself.
			cs.mtx.Lock()
			propBlock, err := cs.createProposalBlock(ctx)
			cs.mtx.Unlock()
			require.NoError(t, err)

			// Make a stub the proposer for round 1 by advancing the round.
			round++
			incrementRound(vss[1:]...)
			prop, propIdx := proposerStubForRound(cs, vss, round)
			require.NotNil(t, prop, "could not find proposer stub for round %d", round)
			require.NotEqual(t, 0, propIdx, "observed validator must not be the proposer")

			// Stamp the block time and proposal timestamp with the skew, relative
			// to the genesis time. At InitialHeight, ValidateBlock requires the
			// block time to equal genesis time, so the timely (offset 0) control
			// uses genesis time exactly. The timeliness gate runs BEFORE
			// ValidateBlock, so the out-of-window cases are rejected by PBTS first.
			// Both the block time and the proposal timestamp must be equal (the
			// gate first requires Proposal.Timestamp == block.Time), so we set both
			// to the same skewed value and exercise the timeliness check.
			genesisTime := cs.state.LastBlockTime // == genesis time at InitialHeight
			skewed := cmttime.Canonical(genesisTime.Add(tc.tsOffset))
			propBlock.Header.Time = skewed

			// Set the proposer address in the header to the chosen proposer.
			ppk, err := prop.GetPubKey()
			require.NoError(t, err)
			propBlock.Header.ProposerAddress = ppk.Address()

			propBlockParts, err := propBlock.MakePartSet(types.BlockPartSizeBytes)
			require.NoError(t, err)
			blockID := types.BlockID{Hash: propBlock.Hash(), PartSetHeader: propBlockParts.Header()}

			proposal := types.NewProposal(height, round, -1, blockID, propBlock.Header.Time)
			pp := proposal.ToProto()
			require.NoError(t, prop.SignProposal(cs.state.ChainID, pp))
			proposal.Signature = pp.Signature

			require.NoError(t, cs.SetProposalAndBlock(proposal, propBlock, propBlockParts, "peerID"))

			startTestRound(cs, height, round)

			ensureNewProposal(proposalCh, height, round)
			ensurePrevote(voteCh, height, round)

			if tc.expectNilVote {
				validatePrevote(t, cs, round, vss[0], nil)
			} else {
				validatePrevote(t, cs, round, vss[0], propBlock.Hash())
			}
		})
	}
}
