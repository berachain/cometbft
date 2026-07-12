//go:build bls12381

package consensus

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	dbm "github.com/cometbft/cometbft-db"

	abci "github.com/cometbft/cometbft/abci/types"
	cstypes "github.com/cometbft/cometbft/consensus/types"
	"github.com/cometbft/cometbft/crypto/bls12381"
	"github.com/cometbft/cometbft/internal/test"
	"github.com/cometbft/cometbft/libs/log"
	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/types"
	cmttime "github.com/cometbft/cometbft/types/time"
)

// blsConsensusNetFromGenesis is like blsConsensusNet but builds the network from
// a CALLER-SUPPLIED genesis doc + priv validators, so a separate late-joiner
// node can be bootstrapped from the very same genesis and catch up.
func blsConsensusNetFromGenesis(
	t *testing.T,
	genDoc *types.GenesisDoc,
	privVals []types.PrivValidator,
	testName string,
) ([]*State, cleanupFunc) {
	t.Helper()
	n := len(privVals)
	css := make([]*State, n)
	logger := consensusLogger()
	configRootDirs := make([]string, 0, n)
	for i := 0; i < n; i++ {
		stateDB := dbm.NewMemDB()
		stateStore := sm.NewStore(stateDB, sm.StoreOptions{DiscardABCIResponses: false})
		state, err := stateStore.LoadFromDBOrGenesisDoc(genDoc)
		require.NoError(t, err)

		thisConfig := ResetConfig(fmt.Sprintf("%s_%d", testName, i))
		configRootDirs = append(configRootDirs, thisConfig.RootDir)
		ensureDir(filepath.Dir(thisConfig.Consensus.WalFile()), 0o700)

		app := newKVStore()
		vals := types.TM2PB.ValidatorUpdates(state.Validators)
		_, err = app.InitChain(context.Background(), &abci.RequestInitChain{Validators: vals})
		require.NoError(t, err)

		css[i] = newStateWithConfigAndBlockStore(thisConfig, state, privVals[i], app, stateDB)
		css[i].SetTimeoutTicker(newMockTickerFunc(false)())
		css[i].SetLogger(logger.With("validator", i, "module", "consensus"))
	}
	return css, func() {
		for _, dir := range configRootDirs {
			os.RemoveAll(dir)
		}
	}
}

// TestAggregationCatchUpViaAddCommit proves the late-joiner / catch-up path for
// aggregated commits: a node that is behind ingests a whole aggregated Commit
// (the CommitMessage gossip payload) via AddCommit, fetches the committed block
// via block-part gossip, and finalizes the height with that aggregated commit in
// its store — all of which then verifies.
//
// It drives the exact load-bearing state-machine path the reactor's
// CommitMessage handler invokes (AddCommit -> enterCommit -> block parts ->
// tryFinalizeCommit -> finalizeCommit), feeding the messages a lagging node would
// receive over the wire.
func TestAggregationCatchUpViaAddCommit(t *testing.T) {
	const N = 4

	// One shared genesis for both the producers and the late joiner.
	genDoc, privVals := blsGenesisDoc(N, 10, blsConsensusParams())
	require.Equal(t, test.DefaultTestChainID, genDoc.ChainID)

	// ---- Producer network: produce a real aggregated commit. ----
	prodCss, cleanup := blsConsensusNetFromGenesis(t, genDoc, privVals, "consensus_agg_catchup_prod")
	defer cleanup()
	require.True(t, prodCss[0].state.Validators.AllKeysHaveSameType())
	require.Equal(t, bls12381.KeyType, prodCss[0].state.Validators.Validators[0].PubKey.Type())

	reactors, blocksSubs, eventBuses := startConsensusNet(t, prodCss, N)
	for j := 0; j < N; j++ {
		go func(j int) {
			for range blocksSubs[j].Out() {
			}
		}(j)
	}

	const producedHeight = int64(3)
	deadline := time.Now().Add(60 * time.Second)
	for prodCss[0].blockStore.Height() < producedHeight {
		if time.Now().After(deadline) {
			stopConsensusNet(log.TestingLogger(), reactors, eventBuses)
			t.Fatalf("producer network did not reach height %d", producedHeight)
		}
		time.Sleep(50 * time.Millisecond)
	}

	const catchUpHeight = int64(1)
	pbs := prodCss[0].blockStore
	block := pbs.LoadBlock(catchUpHeight)
	require.NotNil(t, block)
	blockParts, err := block.MakePartSet(types.BlockPartSizeBytes)
	require.NoError(t, err)
	commit := pbs.LoadBlockCommit(catchUpHeight)
	require.NotNil(t, commit)
	require.True(t, commit.HasAggregatedSignature(),
		"producer commit at height %d is not aggregated", catchUpHeight)

	stopConsensusNet(log.TestingLogger(), reactors, eventBuses)

	// GetState copies under the lock, avoiding a race with any state updates
	// still in flight on the receive routine.
	prodState := prodCss[0].GetState()
	chainID := prodState.ChainID
	genValSet := prodState.Validators.Copy()

	// ---- Late joiner: a fresh node bootstrapped from the same genesis. ----
	lateDB := dbm.NewMemDB()
	lateStateStore := sm.NewStore(lateDB, sm.StoreOptions{DiscardABCIResponses: false})
	lateState, err := lateStateStore.LoadFromDBOrGenesisDoc(genDoc)
	require.NoError(t, err)
	require.EqualValues(t, 0, lateState.LastBlockHeight, "late joiner must start at genesis")

	lateConfig := ResetConfig("consensus_agg_catchup_late")
	t.Cleanup(func() { _ = os.RemoveAll(lateConfig.RootDir) })
	ensureDir(filepath.Dir(lateConfig.Consensus.WalFile()), 0o700)

	app := newKVStore()
	vals := types.TM2PB.ValidatorUpdates(lateState.Validators)
	_, err = app.InitChain(context.Background(), &abci.RequestInitChain{Validators: vals})
	require.NoError(t, err)

	// The late joiner uses a fresh non-validator BLS key: it is catching up, not
	// participating, so it must never propose (which would race the catch-up and
	// try to finalize its own block).
	nonValKey, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	latePV := types.NewMockPVWithParams(nonValKey, false, false)
	late := newStateWithConfigAndBlockStore(lateConfig, lateState, latePV, app, lateDB)
	late.SetTimeoutTicker(newMockTickerFunc(true)())
	late.SetLogger(log.TestingLogger().With("module", "consensus", "node", "late"))

	require.NoError(t, late.Start())
	defer func() { _ = late.Stop() }()

	// Give the state machine a moment to settle at height 1.
	require.Eventually(t, func() bool {
		late.mtx.RLock()
		defer late.mtx.RUnlock()
		return late.Height == catchUpHeight
	}, 5*time.Second, 20*time.Millisecond, "late joiner never reached height 1")

	// Before feeding the real commit, exercise AddCommit's rejection paths. A
	// lagging node adopts a block on the strength of this check alone, so the
	// gate must reject any commit it cannot verify.

	// Forged aggregated signature: flip a byte in the aggregate so BLS
	// verification fails. Expect an error and no adoption.
	forged := commit.Clone()
	for i, s := range forged.Signatures {
		if len(s.Signature) > 0 {
			bad := make([]byte, len(s.Signature))
			copy(bad, s.Signature)
			bad[0] ^= 0xff
			forged.Signatures[i].Signature = bad
			break
		}
	}
	late.mtx.Lock()
	rejAdded, rejErr := late.AddCommit(forged, "byzantine-peer")
	late.mtx.Unlock()
	require.Error(t, rejErr, "AddCommit accepted a forged aggregated signature")
	require.False(t, rejAdded, "forged-signature commit must not be added")

	// Wrong block: the aggregate was signed over a different BlockID, so
	// verification must fail.
	wrongBlock := commit.Clone()
	badHash := make([]byte, len(commit.BlockID.Hash))
	copy(badHash, commit.BlockID.Hash)
	badHash[0] ^= 0xff
	wrongBlock.BlockID.Hash = badHash
	late.mtx.Lock()
	rejAdded, rejErr = late.AddCommit(wrongBlock, "byzantine-peer")
	late.mtx.Unlock()
	require.Error(t, rejErr, "AddCommit accepted a commit for the wrong block")
	require.False(t, rejAdded, "wrong-block commit must not be added")

	// Non-aggregated commit: this fork only adopts aggregated commits via catch-up,
	// so a non-aggregated one is ignored (dropped, but not treated as an error).
	nonAgg := &types.Commit{Height: catchUpHeight, Round: commit.Round, BlockID: commit.BlockID}
	require.False(t, nonAgg.HasAggregatedSignature(), "test setup: nonAgg must not be aggregated")
	late.mtx.Lock()
	rejAdded, rejErr = late.AddCommit(nonAgg, "byzantine-peer")
	late.mtx.Unlock()
	require.NoError(t, rejErr, "non-aggregated commit should be ignored, not error")
	require.False(t, rejAdded, "non-aggregated commit must not be added")

	// None of the rejected commits may have advanced the node or polluted round state.
	late.mtx.RLock()
	require.Nil(t, late.Votes.GetCommit(commit.Round),
		"a rejected commit must not be stored in the HeightVoteSet")
	require.Equal(t, catchUpHeight, late.Height,
		"late joiner must still be at the catch-up height after rejections")
	late.mtx.RUnlock()

	// Feed the aggregated commit through the real ingestion path, a
	// CommitMessage on the peer message queue handled by the receive routine
	// (handleMsg -> AddCommit). AddCommit is the load-bearing catch-up entry
	// point: it
	//   (a) rejects non-aggregated commits,
	//   (b) VERIFIES the aggregated commit against the local validator set
	//       (routing through verifyAggregatedCommit), and
	//   (c) stores it in the HeightVoteSet and enters the commit step.
	// A lagging validator uses this to adopt a block it never voted on.
	// State-mutating calls must run on the receive routine's goroutine (the
	// unlocked RoundState read in receiveRoutine assumes a single writer), so
	// the test must not call AddCommit directly here.
	late.peerMsgQueue <- msgInfo{&CommitMessage{commit}, "producer-peer", cmttime.Now()}
	require.Eventually(t, func() bool {
		late.mtx.RLock()
		defer late.mtx.RUnlock()
		return late.Votes.GetCommit(commit.Round) != nil
	}, 5*time.Second, 20*time.Millisecond,
		"aggregated commit was not added by the late joiner")

	// The aggregated commit is now adopted by the late joiner: it is stored in the
	// round's HeightVoteSet, is aggregated, and verifies against the validator set.
	late.mtx.RLock()
	stored := late.Votes.GetCommit(commit.Round)
	step := late.Step
	late.mtx.RUnlock()
	require.NotNil(t, stored, "late joiner did not adopt the aggregated commit via AddCommit")
	require.True(t, stored.HasAggregatedSignature(),
		"adopted commit is not aggregated: %v", stored)
	require.Equal(t, commit.BlockID, stored.BlockID, "adopted commit has wrong BlockID")
	require.NoError(t,
		genValSet.VerifyCommit(chainID, stored.BlockID, catchUpHeight, stored),
		"late joiner's adopted aggregated commit failed VerifyCommit")

	// AddCommit drove the node into the commit step for the caught-up height,
	// waiting only for the committed block (delivered via block-part gossip).
	require.GreaterOrEqual(t, step, cstypes.RoundStepCommit,
		"AddCommit did not advance the late joiner into the commit step (step=%v)", step)

	t.Logf("late joiner adopted aggregated commit for height %d via AddCommit "+
		"(verified, commit step reached); blockParts available=%d",
		catchUpHeight, blockParts.Total())

	// ---- Deliver the committed block via block-part gossip and finalize. ----
	// AddCommit -> enterCommit set up cs.ProposalBlockParts from the commit's
	// part-set header (the node has the commit but not yet the block). Feeding the
	// parts completes the block, which fires handleCompleteProposal ->
	// tryFinalizeCommit -> finalizeCommit. finalizeCommit's GetCommit branch saves
	// the aggregated seen-commit, and updateToState sets LastCommit = *Commit
	// (the aggregated commit; individual precommit votes cannot be reconstructed)
	// and advances the node to the next height. This is the catch-up *advance*
	// the VoteSetReader/LastCommit change unblocks.
	// Deliver the parts on the peer message queue. The message loop runs
	// addProposalBlockPart, then (once complete) handleCompleteProposal, which
	// in the commit step calls tryFinalizeCommit -> finalizeCommit.
	for i := 0; i < int(blockParts.Total()); i++ {
		part := blockParts.GetPart(i)
		late.peerMsgQueue <- msgInfo{
			&BlockPartMessage{Height: catchUpHeight, Round: commit.Round, Part: part},
			"producer-peer",
			cmttime.Now(),
		}
	}

	// The caught-up node now finalizes the height and ADVANCES past it. This is
	// the gap the inventory's round 4 left open: with LastCommit as a concrete
	// *VoteSet the node could adopt the aggregated commit (reach commit step) but
	// not advance, since votesFromSeenCommit cannot reconstruct the individual
	// precommits of an aggregated commit. With LastCommit as a VoteSetReader and
	// *Commit implementing it, updateToState keeps the *Commit and advances.
	const nextHeight = catchUpHeight + 1
	require.Eventually(t, func() bool {
		late.mtx.RLock()
		defer late.mtx.RUnlock()
		return late.Height == nextHeight
	}, 10*time.Second, 20*time.Millisecond,
		"caught-up node did not advance past the adopted aggregated commit "+
			"(still at height %d, expected %d)", func() int64 {
			late.mtx.RLock()
			defer late.mtx.RUnlock()
			return late.Height
		}(), nextHeight)

	// The committed block is now in the late joiner's own block store, and the
	// stored seen-commit for the caught-up height is the same aggregated commit.
	// (LoadBlockCommit(h) lives in block h+1's LastCommit, which does not exist
	// yet; the locally-justified seen commit is what finalizeCommit saved.)
	storedCommit := late.blockStore.LoadSeenCommit(catchUpHeight)
	require.NotNil(t, storedCommit, "caught-up node did not store the committed block")
	require.True(t, storedCommit.HasAggregatedSignature(),
		"stored commit at caught-up height is not aggregated")
	require.NoError(t,
		genValSet.VerifyCommit(chainID, storedCommit.BlockID, catchUpHeight, storedCommit),
		"caught-up node's stored aggregated commit failed VerifyCommit")
	require.Equal(t, catchUpHeight, late.blockStore.Height(),
		"caught-up node block store height mismatch")

	// And LastCommit is the adopted aggregated *Commit (the VoteSetReader path),
	// not a reconstructed VoteSet.
	late.mtx.RLock()
	lastCommit := late.LastCommit
	late.mtx.RUnlock()
	asCommit, ok := lastCommit.(*types.Commit)
	require.True(t, ok,
		"LastCommit after aggregated catch-up should be a *types.Commit, got %T", lastCommit)
	require.True(t, asCommit.HasAggregatedSignature(),
		"LastCommit *Commit is not aggregated")
	require.Equal(t, commit.BlockID, asCommit.BlockID,
		"LastCommit *Commit has wrong BlockID")

	t.Logf("late joiner finalized height %d via aggregated commit and advanced to height %d "+
		"(LastCommit is the adopted aggregated *Commit)", catchUpHeight, nextHeight)
}
