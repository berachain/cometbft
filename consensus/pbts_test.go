package consensus

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/abci/example/kvstore"
	"github.com/cometbft/cometbft/internal/test"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
	cmttime "github.com/cometbft/cometbft/types/time"
	cmttimemocks "github.com/cometbft/cometbft/types/time/mocks"
)

// TestPBTSProposerWaitTime verifies that proposerWaitTime returns the correct
// amount of time a proposer must wait for its local clock to catch up to the
// previous block time under PBTS.
func TestPBTSProposerWaitTime(t *testing.T) {
	genesisTime, err := time.Parse(time.RFC3339, "2019-03-13T23:00:00Z")
	require.NoError(t, err)
	testCases := []struct {
		name              string
		previousBlockTime time.Time
		localTime         time.Time
		expectedWait      time.Duration
	}{
		{
			name:              "block time greater than local time",
			previousBlockTime: genesisTime.Add(5 * time.Nanosecond),
			localTime:         genesisTime.Add(1 * time.Nanosecond),
			expectedWait:      4 * time.Nanosecond,
		},
		{
			name:              "local time greater than block time",
			previousBlockTime: genesisTime.Add(1 * time.Nanosecond),
			localTime:         genesisTime.Add(5 * time.Nanosecond),
			expectedWait:      0,
		},
		{
			name:              "both times equal",
			previousBlockTime: genesisTime.Add(5 * time.Nanosecond),
			localTime:         genesisTime.Add(5 * time.Nanosecond),
			expectedWait:      0,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mockSource := new(cmttimemocks.Source)
			mockSource.On("Now").Return(testCase.localTime)

			ti := proposerWaitTime(mockSource, testCase.previousBlockTime)
			assert.Equal(t, testCase.expectedWait, ti)
		})
	}
}

// TestPBTSProposalIsTimely verifies the PBTS timeliness window: a proposal is
// timely when the receiver's local clock falls within
// [proposalTime - Precision, proposalTime + MessageDelay + Precision].
func TestPBTSProposalIsTimely(t *testing.T) {
	genesisTime, err := time.Parse(time.RFC3339, "2019-03-13T23:00:00Z")
	require.NoError(t, err)

	sp := types.SynchronyParams{
		Precision:    10 * time.Millisecond,
		MessageDelay: 140 * time.Millisecond,
	}

	testCases := []struct {
		name           string
		proposalTime   time.Time
		recvTime       time.Time
		expectedTimely bool
	}{
		{
			name:           "timely: recv equals proposal time",
			proposalTime:   genesisTime,
			recvTime:       genesisTime,
			expectedTimely: true,
		},
		{
			name:           "timely: recv at lower bound (proposal - precision)",
			proposalTime:   genesisTime,
			recvTime:       genesisTime.Add(-sp.Precision),
			expectedTimely: true,
		},
		{
			name:           "timely: recv at upper bound (proposal + delay + precision)",
			proposalTime:   genesisTime,
			recvTime:       genesisTime.Add(sp.MessageDelay + sp.Precision),
			expectedTimely: true,
		},
		{
			name:           "not timely: too far in the past (recv after upper bound)",
			proposalTime:   genesisTime,
			recvTime:       genesisTime.Add(sp.MessageDelay + sp.Precision + time.Millisecond),
			expectedTimely: false,
		},
		{
			name:           "not timely: too far in the future (recv before lower bound)",
			proposalTime:   genesisTime,
			recvTime:       genesisTime.Add(-sp.Precision - time.Millisecond),
			expectedTimely: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := &types.Proposal{Timestamp: tc.proposalTime}
			assert.Equal(t, tc.expectedTimely, p.IsTimely(tc.recvTime, sp))
		})
	}
}

// TestPBTSSynchronyParamsInRound verifies that the synchrony message delay
// applies an exponential back-off as the round increases, while precision stays
// constant. This is the adaptive component of PBTS.
func TestPBTSSynchronyParamsInRound(t *testing.T) {
	sp := types.SynchronyParams{
		Precision:    10 * time.Millisecond,
		MessageDelay: 100 * time.Millisecond,
	}

	round0 := sp.InRound(0)
	assert.Equal(t, sp.Precision, round0.Precision)
	assert.Equal(t, sp.MessageDelay, round0.MessageDelay)

	// Message delay grows with the round; precision is unchanged.
	round1 := sp.InRound(1)
	assert.Equal(t, sp.Precision, round1.Precision)
	assert.True(t, round1.MessageDelay > sp.MessageDelay,
		"message delay should grow after round 0: got %v, base %v", round1.MessageDelay, sp.MessageDelay)

	round5 := sp.InRound(5)
	assert.True(t, round5.MessageDelay >= round1.MessageDelay,
		"message delay should be non-decreasing in the round")

	// Regression for the overflow behind upstream #4815 (and the round>10
	// bypass it motivated). At very high rounds (303 was observed during a
	// network stall) the exponential back-off must cap at MaxMessageDelay
	// instead of overflowing int64.
	for _, round := range []int32{256, 303, math.MaxInt32} {
		spHigh := types.DefaultSynchronyParams().InRound(round)
		assert.Equal(t, types.MaxMessageDelay, spHigh.MessageDelay,
			"message delay should cap at MaxMessageDelay in round %d", round)
	}
}

// TestPBTSFarFutureProposalRejectedAtHighRound is a regression test for the
// removal of `if cs.Proposal.Round > 10 { return true }` in proposalIsTimely.
//
// With that check in place a malicious proposer at round >10 could get an
// arbitrarily far-future block.Time prevoted by honest validators; once
// committed it poisons LastBlockTime and halts the chain.
func TestPBTSFarFutureProposalRejectedAtHighRound(t *testing.T) {
	const numValidators = 4
	election := func(h int64, r int32) int {
		return (int(h-1) + int(r)) % numValidators
	}

	c := test.ConsensusParams()
	app := kvstore.NewInMemoryApplication()
	genesisTime := cmttime.Now().Add(-10 * time.Second)
	cs, vss := randStateWithAppImplGenesisTime(numValidators, app, c, genesisTime)

	myPubKey, err := vss[0].GetPubKey()
	require.NoError(t, err)
	myAddress := myPubKey.Address()

	proposalCh := subscribe(cs.eventBus, types.EventQueryCompleteProposal)
	newRoundCh := subscribe(cs.eventBus, types.EventQueryNewRound)
	voteCh := subscribe(cs.eventBus, types.EventQueryVote)

	height, round := cs.Height, cs.Round
	chainID := cs.state.ChainID

	// One year ahead
	const farFutureOffset = 365 * 24 * time.Hour
	const lastRound = int32(12)
	sawHighRound := false

	startTestRound(cs, height, round)

	for ; round <= lastRound; round++ {
		t.Log("Starting round", round)
		ensureNewRound(newRoundCh, height, round)
		proposer := election(height, round)

		if proposer == 0 {
			// The observed validator is the proposer: let it propose its own
			// (timely) block; the stubs vote nil to skip the round.
			ensureNewProposal(proposalCh, height, round)
			ensurePrevote(voteCh, height, round)
		} else {
			block, blockParts, blockID := createProposalBlockWithTime(t, cs, cmttime.Now().Add(farFutureOffset))
			proposal := types.NewProposal(height, round, -1, blockID, block.Time)
			signProposal(t, proposal, chainID, vss[proposer])
			require.NoError(t, cs.SetProposalAndBlock(proposal, block, blockParts, "peer"))

			ensureProposal(proposalCh, height, round, blockID)
			ensurePrevote(voteCh, height, round)

			// Ensure far-future proposal have been prevoted nil at any round.
			gotVote := cs.Votes.Prevotes(round).GetByAddress(myAddress)
			require.NotNil(t, gotVote, "observed validator did not prevote at round %d", round)
			require.True(t, gotVote.BlockID.IsNil(),
				"round %d: far-future proposal must be prevoted nil, got block %X",
				round, gotVote.BlockID.Hash)
			if round > 10 {
				sawHighRound = true
			}
		}

		// nil vote for stubs to broadcast to keep advancing in rounds.
		var vote types.BlockID

		for _, vs := range vss[2:] {
			signAddVotes(cs, cmtproto.PrevoteType, vote.Hash, vote.PartSetHeader, false, vs)
			ensurePrevote(voteCh, height, round)
		}
		ensurePrecommit(voteCh, height, round)
		for _, vs := range vss[2:] {
			signAddVotes(cs, cmtproto.PrecommitType, vote.Hash, vote.PartSetHeader, true, vs)
			ensurePrecommit(voteCh, height, round)
		}

		incrementRound(vss[1:]...)
	}

	require.True(t, sawHighRound, "test never exercised a round > 10")
	require.Equal(t, height, cs.Height,
		"a far-future proposal was committed: chain would halt on a poisoned LastBlockTime")
}
