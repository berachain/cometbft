package client_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cryptoenc "github.com/cometbft/cometbft/crypto/encoding"
	"github.com/cometbft/cometbft/crypto/tmhash"
	"github.com/cometbft/cometbft/internal/test"
	cmtrand "github.com/cometbft/cometbft/libs/rand"
	"github.com/cometbft/cometbft/privval"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/rpc/client"
	rpctest "github.com/cometbft/cometbft/rpc/test"
	"github.com/cometbft/cometbft/types"
)

func newEvidence(t *testing.T, val *privval.FilePV,
	vote *types.Vote, vote2 *types.Vote,
	chainID string, evTime time.Time,
) *types.DuplicateVoteEvidence {
	var err error

	v := vote.ToProto()
	v2 := vote2.ToProto()

	vote.Signature, err = val.Key.PrivKey.Sign(types.VoteSignBytes(chainID, v))
	require.NoError(t, err)

	vote2.Signature, err = val.Key.PrivKey.Sign(types.VoteSignBytes(chainID, v2))
	require.NoError(t, err)

	validator := types.NewValidator(val.Key.PubKey, 10)
	valSet := types.NewValidatorSet([]*types.Validator{validator})

	ev, err := types.NewDuplicateVoteEvidence(vote, vote2, evTime, valSet)
	require.NoError(t, err)
	return ev
}

func makeEvidences(
	t *testing.T,
	val *privval.FilePV,
	chainID string,
	evTime time.Time,
) (correct *types.DuplicateVoteEvidence, fakes []*types.DuplicateVoteEvidence) {
	vote := types.Vote{
		ValidatorAddress: val.Key.Address,
		ValidatorIndex:   0,
		Height:           1,
		Round:            0,
		Type:             cmtproto.PrevoteType,
		BlockID: types.BlockID{
			Hash: tmhash.Sum(cmtrand.Bytes(tmhash.Size)),
			PartSetHeader: types.PartSetHeader{
				Total: 1000,
				Hash:  tmhash.Sum([]byte("partset")),
			},
		},
	}

	vote2 := vote
	vote2.BlockID.Hash = tmhash.Sum([]byte("blockhash2"))
	correct = newEvidence(t, val, &vote, &vote2, chainID, evTime)

	fakes = make([]*types.DuplicateVoteEvidence, 0)

	// different address
	{
		v := vote2
		v.ValidatorAddress = []byte("some_address")
		fakes = append(fakes, newEvidence(t, val, &vote, &v, chainID, evTime))
	}

	// different height
	{
		v := vote2
		v.Height = vote.Height + 1
		fakes = append(fakes, newEvidence(t, val, &vote, &v, chainID, evTime))
	}

	// different round
	{
		v := vote2
		v.Round = vote.Round + 1
		fakes = append(fakes, newEvidence(t, val, &vote, &v, chainID, evTime))
	}

	// different type
	{
		v := vote2
		v.Type = cmtproto.PrecommitType
		fakes = append(fakes, newEvidence(t, val, &vote, &v, chainID, evTime))
	}

	// exactly same vote
	{
		v := vote
		fakes = append(fakes, newEvidence(t, val, &vote, &v, chainID, evTime))
	}

	return correct, fakes
}

func TestBroadcastEvidence_DuplicateVoteEvidence(t *testing.T) {
	var (
		config  = rpctest.GetConfig()
		chainID = test.DefaultTestChainID
		pv      = privval.LoadOrGenFilePV(config.PrivValidatorKeyFile(), config.PrivValidatorStateFile())
	)

	for i, c := range GetClients() {
		t.Logf("client %d", i)

		// The evidence is for height 1; make sure the node has committed the
		// block at that height before broadcasting. Under PBTS the block time
		// is the proposer's wall clock, so the evidence must be stamped with
		// the actual block time.
		require.NoError(t, client.WaitForHeight(c, 1, nil))
		h := int64(1)
		blk, err := c.Block(context.Background(), &h)
		require.NoError(t, err)
		correct, fakes := makeEvidences(t, pv, chainID, blk.Block.Time)

		result, err := c.BroadcastEvidence(context.Background(), correct)
		require.NoError(t, err, "BroadcastEvidence(%s) failed", correct)
		assert.Equal(t, correct.Hash(), result.Hash, "expected result hash to match evidence hash")

		status, err := c.Status(context.Background())
		require.NoError(t, err)
		err = client.WaitForHeight(c, status.SyncInfo.LatestBlockHeight+2, nil)
		require.NoError(t, err)

		ed25519pub := pv.Key.PubKey.(ed25519.PubKey)
		rawpub := ed25519pub.Bytes()
		result2, err := c.ABCIQuery(context.Background(), "/val", rawpub)
		require.NoError(t, err)
		qres := result2.Response
		require.True(t, qres.IsOK())

		var v abci.ValidatorUpdate
		err = abci.ReadMessage(bytes.NewReader(qres.Value), &v)
		require.NoError(t, err, "Error reading query result, value %v", qres.Value)

		pk, err := cryptoenc.PubKeyFromProto(v.PubKey)
		require.NoError(t, err)

		require.EqualValues(t, rawpub, pk, "Stored PubKey not equal with expected, value %v", string(qres.Value))
		require.Equal(t, int64(9), v.Power, "Stored Power not equal with expected, value %v", string(qres.Value))

		for _, fake := range fakes {
			_, err := c.BroadcastEvidence(context.Background(), fake)
			require.Error(t, err, "BroadcastEvidence(%s) succeeded, but the evidence was fake", fake)
		}
	}
}

func TestBroadcastEmptyEvidence(t *testing.T) {
	for _, c := range GetClients() {
		_, err := c.BroadcastEvidence(context.Background(), nil)
		assert.Error(t, err)
	}
}
