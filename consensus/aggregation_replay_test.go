//go:build bls12381

package consensus

import (
	"context"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	dbm "github.com/cometbft/cometbft-db"

	abci "github.com/cometbft/cometbft/abci/types"
	cfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sm "github.com/cometbft/cometbft/state"
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

// TestAggregationWALReplayRestart crashes a BLS+PBTS validator right after it
// signed its prevote at crashHeight but before the prevote reached the WAL,
// then restarts it once the proposal's timeliness window has passed. Replaying
// the proposal with its persisted receive time must reproduce the same prevote,
// so the disk-backed FilePV returns the stored signature instead of refusing a
// conflicting vote, and the node goes on to commit new aggregated blocks.
func TestAggregationWALReplayRestart(t *testing.T) {
	const crashHeight = int64(3)
	cp := blsConsensusParams()
	cp.Synchrony.MessageDelay = 500 * time.Millisecond
	cp.Synchrony.Precision = 10 * time.Millisecond
	genDoc, privVals := blsGenesisDoc(1, 10, cp)

	thisConfig := ResetConfig("aggregation_wal_replay")
	ensureDir(filepath.Dir(thisConfig.Consensus.WalFile()), 0o700)
	blockDB := dbm.NewMemDB()
	app := newPersistentKVStoreWithPath(filepath.Join(thisConfig.DBDir(), "agg_replay_app"))
	keyFile, stateFile := filepath.Join(thisConfig.RootDir, "pv_key.json"), filepath.Join(thisConfig.RootDir, "pv_state.json")
	privval.NewFilePV(privVals[0].(types.MockPV).PrivKey, keyFile, stateFile).Save()

	// Phase 1: run until the prevote at crashHeight is signed, then crash.
	cs1 := buildBLSState(t, thisConfig, genDoc, privval.LoadFilePV(keyFile, stateFile), app, blockDB)
	cs1.SetTimeoutTicker(newMockTickerFunc(true)())
	wal, err := cs1.OpenWAL(thisConfig.Consensus.WalFile())
	require.NoError(t, err)
	crashed := make(chan struct{})
	cs1.wal = &crashOnPrevoteWAL{WAL: wal, height: crashHeight, crashed: crashed}
	require.NoError(t, cs1.Start())
	select {
	case <-crashed:
	case <-time.After(10 * time.Second):
		t.Fatalf("no prevote at height %d", crashHeight)
	}
	_ = cs1.Stop()
	_ = wal.Stop()

	// Restart only after the proposal would no longer be timely by wall clock.
	time.Sleep(cp.Synchrony.MessageDelay + cp.Synchrony.Precision + 300*time.Millisecond)

	// Phase 2: restart over the same block store, app, WAL and FilePV state.
	pv := &signErrPV{PrivValidator: privval.LoadFilePV(keyFile, stateFile)}
	cs2 := buildBLSState(t, thisConfig, genDoc, pv, app, blockDB)
	cs2.SetTimeoutTicker(newMockTickerFunc(true)())
	newBlockCh := subscribe(cs2.eventBus, types.EventQueryNewBlock)
	require.NoError(t, cs2.Start())
	defer func() { _ = cs2.Stop() }()
	for h := int64(0); h <= crashHeight; {
		select {
		case msg := <-newBlockCh:
			h = msg.Data().(types.EventDataNewBlock).Block.Height
		case <-time.After(10 * time.Second):
			t.Fatalf("no new block after restart (vote signing errors: %v)", pv.errors())
		}
	}
	require.Empty(t, pv.errors(), "restart signed a conflicting vote")

	valSet, err := sm.MakeGenesisState(genDoc)
	require.NoError(t, err)
	for h := int64(1); h <= crashHeight; h++ {
		commit := cs2.blockStore.LoadBlockCommit(h)
		require.True(t, commit.HasAggregatedSignature(), "height %d", h)
		require.NoError(t, valSet.Validators.VerifyCommit(genDoc.ChainID, commit.BlockID, h, commit))
	}
}

// crashOnPrevoteWAL stops the consensus receive routine, like a crash, when the
// node's own prevote at height is about to be written.
type crashOnPrevoteWAL struct {
	WAL
	height  int64
	crashed chan struct{}
}

func (w *crashOnPrevoteWAL) Write(m WALMessage) error {
	if mi, ok := m.(msgInfo); ok && mi.PeerID == "" {
		if vm, ok := mi.Msg.(*VoteMessage); ok && vm.Vote.Type == cmtproto.PrevoteType && vm.Vote.Height == w.height {
			close(w.crashed)
			runtime.Goexit()
		}
	}
	return w.WAL.Write(m)
}

func (w *crashOnPrevoteWAL) WriteSync(m WALMessage) error { return w.Write(m) }

// signErrPV records the errors returned when signing votes.
type signErrPV struct {
	types.PrivValidator
	mtx  sync.Mutex
	errs []error
}

func (pv *signErrPV) SignVote(chainID string, vote *cmtproto.Vote) error {
	err := pv.PrivValidator.SignVote(chainID, vote)
	if err != nil {
		pv.mtx.Lock()
		pv.errs = append(pv.errs, err)
		pv.mtx.Unlock()
	}
	return err
}

func (pv *signErrPV) errors() []error {
	pv.mtx.Lock()
	defer pv.mtx.Unlock()
	return pv.errs
}
