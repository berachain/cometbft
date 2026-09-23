//go:build bls12381

package consensus

import (
	"testing"

	"github.com/go-kit/kit/metrics"
	"github.com/stretchr/testify/require"

	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/types"
)

// TestIngestAggregatedCommit checks that blocks whose commits are aggregated
// can be ingested (the adaptive sync path). The individual precommits cannot
// be rebuilt from an aggregated commit, so the whole commit must become
// cs.LastCommit, and the node must still be able to propose on top of it.
// It also checks that an aggregated signature counts as our validator having
// signed in the validator metrics.
func TestIngestAggregatedCommit(t *testing.T) {
	genDoc, privVals := blsGenesisDoc(4, 10, blsConsensusParams())
	state, err := sm.MakeGenesisState(genDoc)
	require.NoError(t, err)

	cs := newState(state, privVals[0], newKVStore())
	lastSigned := &recordingGauge{}
	missed := &recordingGauge{}
	cs.metrics.ValidatorLastSignedHeight = lastSigned
	cs.metrics.ValidatorMissedBlocks = missed

	vss := make([]*validatorStub, len(privVals))
	for i, pv := range privVals {
		vss[i] = newValidatorStub(pv, int32(i))
	}
	ts := &ingestTestSuite{t: t, cs: cs, validators: vss, aggregate: true}

	for range 3 {
		// createProposalBlock builds on cs.LastCommit, which after the first
		// round is the whole aggregated commit set by the previous ingest.
		ic := ts.MakeIngestCandidateUnverified()
		require.True(t, ic.commit.HasAggregatedSignature())
		require.NoError(t, ic.Verify(cs.state))

		require.NoError(t, ts.IngestVerifiedBlock(ic))
		require.Equal(t, ic.Height(), cs.GetLastHeight())

		lastCommit, ok := cs.LastCommit.(*types.Commit)
		require.True(t, ok, "LastCommit should be the whole aggregated commit, got %T", cs.LastCommit)
		require.Equal(t, ic.Height(), lastCommit.Height)
		require.True(t, lastCommit.HasAggregatedSignature())
	}

	// Blocks 2 and 3 carry an aggregated LastCommit that includes our
	// validator.
	require.Equal(t, []float64{2, 3}, lastSigned.set)
	require.Zero(t, missed.added)
}

// recordingGauge records the values set and the sum of the values added.
type recordingGauge struct {
	set   []float64
	added float64
}

func (g *recordingGauge) With(...string) metrics.Gauge { return g }
func (g *recordingGauge) Set(v float64)                { g.set = append(g.set, v) }
func (g *recordingGauge) Add(v float64)                { g.added += v }
