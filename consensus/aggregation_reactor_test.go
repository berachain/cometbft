//go:build bls12381

package consensus

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	dbm "github.com/cometbft/cometbft-db"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/bls12381"
	"github.com/cometbft/cometbft/internal/test"
	"github.com/cometbft/cometbft/libs/log"
	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/types"
	cmttime "github.com/cometbft/cometbft/types/time"
)

// blsConsensusParams returns consensus params suitable for BLS aggregation:
// PBTS enabled from height 1 (required, since aggregation strips the per-vote
// timestamp so every validator signs identical bytes) and vote extensions
// disabled (the aggregated-commit path does not support extensions).
func blsConsensusParams() *types.ConsensusParams {
	c := types.DefaultConsensusParams()
	c.Feature.VoteExtensionsEnableHeight = 0 // disabled
	c.Feature.VoteExtensionsEnableHeight = 0
	c.Feature.PbtsEnableHeight = 1 // PBTS on from genesis
	return c
}

// blsGenesisDoc builds a genesis doc whose validators all use bls12_381 keys,
// returning the matching MockPV priv validators (sorted by address, as the
// harness expects).
func blsGenesisDoc(numValidators int, votingPower int64, consensusParams *types.ConsensusParams) (*types.GenesisDoc, []types.PrivValidator) {
	validators := make([]types.GenesisValidator, numValidators)
	privValidators := make([]types.PrivValidator, numValidators)
	for i := 0; i < numValidators; i++ {
		privKey, err := bls12381.GenPrivKey()
		if err != nil {
			panic(fmt.Errorf("could not generate BLS priv key: %w", err))
		}
		privVal := types.NewMockPVWithParams(privKey, false, false)
		pubKey, err := privVal.GetPubKey()
		if err != nil {
			panic(err)
		}
		validators[i] = types.GenesisValidator{
			PubKey: pubKey,
			Power:  votingPower,
		}
		privValidators[i] = privVal
	}
	sort.Sort(types.PrivValidatorsByAddress(privValidators))

	return &types.GenesisDoc{
		GenesisTime:     cmttime.Now(),
		InitialHeight:   1,
		ChainID:         test.DefaultTestChainID,
		Validators:      validators,
		ConsensusParams: consensusParams,
	}, privValidators
}

// blsConsensusNet spins up nValidators in-process consensus States, all using
// BLS keys, with PBTS enabled. Mirrors randConsensusNet but with a BLS genesis.
func blsConsensusNet(t *testing.T, nValidators int, testName string) ([]*State, cleanupFunc) {
	t.Helper()
	genDoc, privVals := blsGenesisDoc(nValidators, 10, blsConsensusParams())
	css := make([]*State, nValidators)
	logger := consensusLogger()
	configRootDirs := make([]string, 0, nValidators)
	for i := 0; i < nValidators; i++ {
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

// TestReactorAggregatedCommits is the win-condition test: a multi-validator
// network using BLS keys + PBTS produces aggregated commits (BlockIDFlagAgg*)
// over the real network/consensus path, makes progress across several heights
// (liveness), and the aggregated commits verify via VerifyCommit (which routes
// through verifyAggregatedCommit).
func TestReactorAggregatedCommits(t *testing.T) {
	N := 4
	css, cleanup := blsConsensusNet(t, N, "consensus_agg_reactor_test")
	defer cleanup()

	// Sanity: all validators carry BLS keys, so the aggregation path is taken.
	require.True(t, css[0].state.Validators.AllKeysHaveSameType())
	require.Equal(t, bls12381.KeyType, css[0].state.Validators.Validators[0].PubKey.Type(),
		"validators must use bls12381 keys")

	reactors, blocksSubs, eventBuses := startConsensusNet(t, css, N)
	defer stopConsensusNet(log.TestingLogger(), reactors, eventBuses)

	// Wait until every validator commits several blocks (liveness). We drain the
	// new-block subscriptions continuously in the background so the event bus
	// never back-pressures and stalls consensus, while tracking the max height
	// each validator has reached.
	const targetHeight = 4
	heights := make([]int64, N)
	var hmtx sync.Mutex
	for j := 0; j < N; j++ {
		go func(j int) {
			for msg := range blocksSubs[j].Out() {
				if nb, ok := msg.Data().(types.EventDataNewBlock); ok {
					hmtx.Lock()
					if nb.Block.Height > heights[j] {
						heights[j] = nb.Block.Height
					}
					hmtx.Unlock()
				}
			}
		}(j)
	}

	deadline := time.Now().Add(60 * time.Second)
	for {
		hmtx.Lock()
		min := int64(1 << 62)
		for _, h := range heights {
			if h < min {
				min = h
			}
		}
		hmtx.Unlock()
		if min >= targetHeight {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("liveness stall: heights=%v, did not all reach %d", heights, targetHeight)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Give the last commit a moment to be persisted everywhere.
	time.Sleep(500 * time.Millisecond)

	// Assert the real properties on every validator's block store.
	chainID := css[0].state.ChainID
	checkedAgg := 0
	for i := 0; i < N; i++ {
		bs := css[i].blockStore
		valSet := css[i].state.Validators // genesis valset (unchanged across these heights)
		require.GreaterOrEqual(t, bs.Height(), int64(targetHeight),
			"validator %d only reached height %d", i, bs.Height())

		// For each committed height, the seen commit must be aggregated and verify.
		for h := int64(1); h <= bs.Height()-1; h++ {
			block := bs.LoadBlock(h)
			require.NotNil(t, block, "validator %d missing block %d", i, h)

			// The commit stored at h+1's LastCommit / seen commit for h.
			commit := bs.LoadBlockCommit(h)
			if commit == nil {
				commit = bs.LoadSeenCommit(h)
			}
			require.NotNil(t, commit, "validator %d missing commit for height %d", i, h)

			require.True(t, commit.HasAggregatedSignature(),
				"validator %d commit at height %d is NOT aggregated: %v", i, h, commit)

			// The commit's BlockID must match the block it commits.
			require.Equal(t, block.Hash().Bytes(), commit.BlockID.Hash.Bytes(),
				"validator %d commit blockID mismatch at height %d", i, h)

			err := valSet.VerifyCommit(chainID, commit.BlockID, h, commit)
			require.NoError(t, err,
				"validator %d aggregated commit at height %d failed VerifyCommit", i, h)
			checkedAgg++
		}
	}
	require.Positive(t, checkedAgg, "no aggregated commits were checked")
	t.Logf("verified %d aggregated commits across %d validators up to height %d",
		checkedAgg, N, css[0].blockStore.Height())
}
