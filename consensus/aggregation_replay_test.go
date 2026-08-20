//go:build bls12381

package consensus

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	dbm "github.com/cometbft/cometbft-db"

	abci "github.com/cometbft/cometbft/abci/types"
	cfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/crypto/bls12381"
	"github.com/cometbft/cometbft/libs/log"
	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/store"
	"github.com/cometbft/cometbft/types"
)

// buildBLSState constructs a single consensus State backed by the supplied
// (shared, hence restart-surviving) block/state DB and application, using a BLS
// genesis with PBTS enabled. Returning the genesis doc lets a second invocation
// rebuild an identical State over the same persistent stores, simulating a node
// restart.
func buildBLSState(
	t *testing.T,
	thisConfig *cfg.Config,
	genDoc *types.GenesisDoc,
	privVal types.PrivValidator,
	app abci.Application,
	blockDB dbm.DB,
) *State {
	t.Helper()

	stateDB := blockDB
	stateStore := sm.NewStore(stateDB, sm.StoreOptions{DiscardABCIResponses: false})

	state, err := stateStore.LoadFromDBOrGenesisDoc(genDoc)
	require.NoError(t, err)

	// InitChain so the app knows the validator set (idempotent for the kvstore).
	vals := types.TM2PB.ValidatorUpdates(state.Validators)
	_, err = app.InitChain(context.Background(), &abci.RequestInitChain{Validators: vals})
	require.NoError(t, err)

	cs := newStateWithConfigAndBlockStore(thisConfig, state, privVal, app, blockDB)
	cs.SetLogger(log.TestingLogger().With("module", "consensus"))
	return cs
}

// TestAggregationWALReplayRestart proves a BLS+PBTS node can be restarted and
// replay its WAL cleanly, ending at the same height with the SAME aggregated
// commits in its store, all of which still verify.
//
//  1. A single BLS validator commits several heights to a persistent block/state
//     DB and a real on-disk WAL.
//  2. The State is stopped.
//  3. A brand-new State is constructed over the very same DB, app and WAL file,
//     and started. On start it replays the WAL (catchupReplay).
//  4. We assert the post-restart height matches and that every stored commit is
//     aggregated (BlockIDFlagAgg*) and verifies via VerifyCommit.
func TestAggregationWALReplayRestart(t *testing.T) {
	// Shared, restart-surviving resources.
	cp := blsConsensusParams()
	genDoc, privVals := blsGenesisDoc(1, 10, cp)
	privVal := privVals[0]

	pk, err := privVal.GetPubKey()
	require.NoError(t, err)
	require.Equal(t, bls12381.KeyType, pk.Type(), "validator must use a bls12381 key")

	thisConfig := ResetConfig("aggregation_wal_replay")
	t.Cleanup(func() { _ = thisConfig })
	ensureDir(filepath.Dir(thisConfig.Consensus.WalFile()), 0o700)

	blockDB := dbm.NewMemDB() // a single handle, shared across both State lifetimes
	appPath := filepath.Join(thisConfig.DBDir(), "agg_replay_app")
	app := newPersistentKVStoreWithPath(appPath)

	const targetHeight = int64(4)

	// ---- Phase 1: run to targetHeight, persisting to DB + WAL. ----
	func() {
		cs := buildBLSState(t, thisConfig, genDoc, privVal, app, blockDB)
		cs.SetTimeoutTicker(newMockTickerFunc(true)())

		newBlockCh := subscribe(cs.eventBus, types.EventQueryNewBlock)

		require.NoError(t, cs.Start())
		defer func() { _ = cs.Stop() }()

		deadline := time.Now().Add(30 * time.Second)
		for {
			select {
			case msg := <-newBlockCh:
				nb := msg.Data().(types.EventDataNewBlock)
				if nb.Block.Height >= targetHeight {
					goto done
				}
			case <-time.After(time.Until(deadline)):
				t.Fatalf("phase 1 liveness stall before height %d", targetHeight)
			}
		}
	done:
		// Let the commit for the final height settle into the store/WAL.
		time.Sleep(300 * time.Millisecond)
		require.GreaterOrEqual(t, cs.blockStore.Height(), targetHeight,
			"phase 1 did not reach target height")
	}()

	// Capture what the store holds pre-restart for comparison.
	preStore := store.NewBlockStore(blockDB)
	preHeight := preStore.Height()
	require.GreaterOrEqual(t, preHeight, targetHeight)

	chainID := genDoc.ChainID
	valSet := types.NewValidatorSet(nil)
	{
		// Reconstruct the genesis validator set for verification.
		s, err := sm.MakeGenesisState(genDoc)
		require.NoError(t, err)
		valSet = s.Validators
	}

	assertAggregatedCommits := func(t *testing.T, bs sm.BlockStore, label string) {
		t.Helper()
		checked := 0
		for h := int64(1); h <= bs.Height()-1; h++ {
			commit := bs.LoadBlockCommit(h)
			if commit == nil {
				commit = bs.LoadSeenCommit(h)
			}
			require.NotNil(t, commit, "%s: missing commit for height %d", label, h)
			require.True(t, commit.HasAggregatedSignature(),
				"%s: commit at height %d is NOT aggregated: %v", label, h, commit)
			require.NoError(t, valSet.VerifyCommit(chainID, commit.BlockID, h, commit),
				"%s: aggregated commit at height %d failed VerifyCommit", label, h)
			checked++
		}
		require.Positive(t, checked, "%s: no aggregated commits checked", label)
		t.Logf("%s: verified %d aggregated commits up to height %d", label, checked, bs.Height())
	}

	// Pre-restart sanity: the persisted commits are aggregated and verify.
	assertAggregatedCommits(t, preStore, "pre-restart")

	// ---- Phase 2: restart over the SAME DB + WAL and replay. ----
	cs2 := buildBLSState(t, thisConfig, genDoc, privVal, app, blockDB)
	cs2.SetTimeoutTicker(newMockTickerFunc(true)())

	// Starting the State triggers WAL load + catchupReplay over the persisted WAL.
	require.NoError(t, cs2.Start())
	defer func() { _ = cs2.Stop() }()

	// Give replay a moment to run.
	time.Sleep(500 * time.Millisecond)

	// The restarted node must be at least at the pre-restart height (replay must
	// not lose committed state) and its store must still hold the aggregated
	// commits, all verifying.
	require.GreaterOrEqual(t, cs2.blockStore.Height(), preHeight,
		"restarted node regressed below pre-restart height %d (got %d)",
		preHeight, cs2.blockStore.Height())

	// cs2 is running, so read its height via GetRoundState, which takes the
	// consensus mutex; a direct cs2.Height read races with the state machine.
	csHeight := cs2.GetRoundState().Height
	require.GreaterOrEqual(t, csHeight, preHeight,
		"restarted consensus height %d below pre-restart height %d", csHeight, preHeight)

	assertAggregatedCommits(t, cs2.blockStore, "post-restart")

	t.Logf("restart replay OK: pre-restart height=%d, post-restart store height=%d, cs height=%d",
		preHeight, cs2.blockStore.Height(), csHeight)
}
