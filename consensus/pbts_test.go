package consensus

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/types"
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
}
