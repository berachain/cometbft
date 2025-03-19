package consensus

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbm "github.com/cometbft/cometbft-db"
	cfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/crypto/merkle"
	"github.com/cometbft/cometbft/crypto/tmhash"
	"github.com/cometbft/cometbft/internal/autofile"
	"github.com/cometbft/cometbft/internal/consensus/types"
	cmtrand "github.com/cometbft/cometbft/internal/rand"
	"github.com/cometbft/cometbft/internal/test"
	"github.com/cometbft/cometbft/libs/log"
	sm "github.com/cometbft/cometbft/state"
	cmttypes "github.com/cometbft/cometbft/types"
	cmttime "github.com/cometbft/cometbft/types/time"
)

const (
	walTestFlushInterval = time.Duration(100) * time.Millisecond
)

func TestWALTruncate(t *testing.T) {
	const numBlocks = 60

	var (
		walDir  = t.TempDir()
		walFile = filepath.Join(walDir, "wal")
	)
	// this magic number 4K can truncate the content when RotateFile.
	// defaultHeadSizeLimit(10M) is hard to simulate.
	// this magic number 1 * time.Millisecond make RotateFile check frequently.
	// defaultGroupCheckDuration(5s) is hard to simulate.
	wal, err := NewWAL(walFile,
		autofile.GroupHeadSizeLimit(4096),
		autofile.GroupCheckDuration(1*time.Millisecond),
	)
	require.NoError(t, err)

	wal.SetLogger(log.TestingLogger())

	err = wal.Start()
	require.NoError(t, err)

	defer func() {
		if err := wal.Stop(); err != nil {
			t.Error(err)
		}
		// wait for the wal to finish shutting down so we
		// can safely remove the directory
		wal.Wait()
	}()

	// 60 block's size nearly 70K, greater than group's headBuf size(4096 * 10),
	// when headBuf is full, truncate content will Flush to the file. at this
	// time, RotateFile is called, truncate content exist in each file.
	err = WALGenerateNBlocks(t, wal.Group(), numBlocks, getConfig(t))
	require.NoError(t, err)

	time.Sleep(1 * time.Millisecond) // wait groupCheckDuration, make sure RotateFile run

	if err := wal.FlushAndSync(); err != nil {
		t.Error(err)
	}

	h := int64(50)
	gr, found, err := wal.SearchForEndHeight(h, &WALSearchOptions{})
	require.NoError(t, err, "expected not to err on height %d", h)
	assert.True(t, found, "expected to find end height for %d", h)
	assert.NotNil(t, gr)
	defer gr.Close()

	dec := NewWALDecoder(gr)
	msg, err := dec.Decode()
	require.NoError(t, err, "expected to decode a message")
	rs, ok := msg.Msg.(cmttypes.EventDataRoundState)
	assert.True(t, ok, "expected message of type EventDataRoundState")
	assert.Equal(t, rs.Height, h+1, "wrong height")
}

func TestWALEncoderDecoder(t *testing.T) {
	var (
		now      = cmttime.Now()
		cs1, vss = randState(1)

		randBlkBytes = cmtrand.Bytes(tmhash.Size)
		blkID        = cmttypes.BlockID{
			Hash:          randBlkBytes,
			PartSetHeader: cmttypes.PartSetHeader{Total: 5, Hash: randBlkBytes},
		}

		randBlobBytes = cmtrand.Bytes(tmhash.Size)
		blobID        = cmttypes.BlobID{
			Hash:          randBlobBytes,
			PartSetHeader: cmttypes.PartSetHeader{Total: 5, Hash: randBlobBytes},
		}

		proposal = cmttypes.Proposal{
			Type:      cmttypes.ProposalType,
			Height:    42,
			Round:     13,
			BlockID:   blkID,
			POLRound:  12,
			Timestamp: cmttime.Canonical(now),
			BlobID:    blobID,
		}
		protoProposal = proposal.ToProto()
	)

	err := vss[0].SignProposal(cs1.state.ChainID, protoProposal)
	require.NoError(t, err)

	proposal.Signature = protoProposal.Signature

	msgs := []TimedWALMessage{
		{Time: now, Msg: EndHeightMessage{0}},
		{
			Time: now,
			Msg: timeoutInfo{
				Duration: time.Second,
				Height:   1,
				Round:    1,
				Step:     types.RoundStepPropose,
			},
		},
		{
			Time: now,
			Msg: cmttypes.EventDataRoundState{
				Height: 1,
				Round:  1,
				Step:   "",
			},
		},
		{
			Time: now,
			Msg: msgInfo{
				Msg:         &ProposalMessage{Proposal: &proposal},
				PeerID:      "Nobody",
				ReceiveTime: now,
			},
		},
		{
			Time: now,
			Msg: msgInfo{
				Msg:         &ProposalMessage{Proposal: &proposal},
				PeerID:      "Nobody",
				ReceiveTime: time.Time{},
			},
		},
		{
			Time: now,
			Msg: msgInfo{
				Msg:    &ProposalMessage{Proposal: &proposal},
				PeerID: "Nobody",
			},
		},
		{
			Time: now,
			Msg: msgInfo{
				Msg: &BlobPartMessage{
					Height: 1,
					Round:  1,
					Part: &cmttypes.Part{
						Index: 1,
						Bytes: []byte("blob"),
						Proof: merkle.Proof{
							Total:    1,
							Index:    1,
							LeafHash: cmtrand.Bytes(tmhash.Size),
							Aunts:    nil,
						},
					},
				},
				PeerID:      "Nobody",
				ReceiveTime: now,
			},
		},
	}

	b := new(bytes.Buffer)
	for _, msg := range msgs {
		b.Reset()

		enc := NewWALEncoder(b)
		err := enc.Encode(&msg)
		require.NoError(t, err)

		dec := NewWALDecoder(b)
		decoded, err := dec.Decode()
		require.NoError(t, err)
		assert.Equal(t, msg.Time.UTC(), decoded.Time)
		assert.Equal(t, msg.Msg, decoded.Msg)
	}
}

func TestWALEncoderDecoderMultiVersion(t *testing.T) {
	now := time.Time{}.AddDate(100, 10, 20)

	v100Data, err := hex.DecodeString(
		"c6c4eff3000000e50a0b0880e2c3b1a4feffffff0112d50112d2010ac7011ac4010ac1010820102a180d200c2a480a2001c073624aaf3978514ef8443bb2a859c75fc3cc6af26d5aaa20926f046baa6612240805122001c073624aaf3978514ef8443bb2a859c75fc3cc6af26d5aaa20926f046baa66320b0880e2c3b1a4feffffff013a608a0c44b5f0476fe9ad5a655e446efc715b97e88f45e4ff200e945892c5c036946b63dd3a6199023aebf3ef58a03c979908cd22ca081b786a0f4f38f0508d6febea456ad5078018dc752550dfd5c41f4d1588f27dd96e8846e2fff6d3121d75bd12064e6f626f6479",
	)
	require.NoError(t, err)

	var (
		ss, privVals = makeState(1, "execution_chain")
		pVal         cmttypes.PrivValidator
	)
	for mk := range privVals {
		pVal = privVals[mk]
	}
	vs := newValidatorStub(pVal, 1)

	cmtrand.Seed(0)

	var (
		randBlkBytes = cmtrand.Bytes(tmhash.Size)
		blk          = cmttypes.BlockID{
			Hash:          randBlkBytes,
			PartSetHeader: cmttypes.PartSetHeader{Total: 5, Hash: randBlkBytes},
		}

		proposal = cmttypes.Proposal{
			Type:      cmttypes.ProposalType,
			Height:    42,
			Round:     13,
			BlockID:   blk,
			POLRound:  12,
			Timestamp: cmttime.Canonical(now),
			BlobID:    cmttypes.BlobID{},
		}
		protoProposal = proposal.ToProto()
	)
	err = vs.SignProposal(ss.ChainID, protoProposal)
	require.NoError(t, err)

	proposal.Signature = protoProposal.Signature

	cases := []struct {
		twm           TimedWALMessage
		expectFailure bool
	}{
		{
			twm: TimedWALMessage{
				Time: now,
				Msg: msgInfo{
					Msg:         &ProposalMessage{Proposal: &proposal},
					PeerID:      "Nobody",
					ReceiveTime: now,
				},
			},
			expectFailure: true,
		},
		{
			twm: TimedWALMessage{
				Time: now,
				Msg: msgInfo{
					Msg:         &ProposalMessage{Proposal: &proposal},
					PeerID:      "Nobody",
					ReceiveTime: time.Time{},
				},
			},
			expectFailure: false,
		},
		{
			twm: TimedWALMessage{
				Time: now,
				Msg: msgInfo{
					Msg:    &ProposalMessage{Proposal: &proposal},
					PeerID: "Nobody",
				},
			},
			expectFailure: false,
		},
	}

	b := new(bytes.Buffer)

	_, err = b.Write(v100Data)
	require.NoError(t, err)

	dec := NewWALDecoder(b)
	v100decoded, err := dec.Decode()
	require.NoError(t, err)

	var (
		twmV100     = v100decoded.Msg
		msgInfoV100 = twmV100.(msgInfo)
	)
	for _, tc := range cases {
		if tc.expectFailure {
			assert.NotEqual(t, tc.twm.Msg, msgInfoV100)
		} else {
			assert.Equal(t, tc.twm.Msg, msgInfoV100)
		}
	}
}

func TestWALEncoder(t *testing.T) {
	var (
		now = time.Time{}.AddDate(100, 10, 20)

		ss, privVals = makeState(1, "execution_chain")
		pVal         cmttypes.PrivValidator
	)
	for mk := range privVals {
		pVal = privVals[mk]
	}

	valStub := newValidatorStub(pVal, 1)

	cmtrand.Seed(0)

	var (
		randBlkBytes = cmtrand.Bytes(tmhash.Size)
		blk          = cmttypes.BlockID{
			Hash:          randBlkBytes,
			PartSetHeader: cmttypes.PartSetHeader{Total: 5, Hash: randBlkBytes},
		}

		randBlobBytes = cmtrand.Bytes(tmhash.Size)
		blobID        = cmttypes.BlobID{
			Hash:          randBlobBytes,
			PartSetHeader: cmttypes.PartSetHeader{Total: 5, Hash: randBlobBytes},
		}

		proposal = cmttypes.Proposal{
			Type:      cmttypes.ProposalType,
			Height:    42,
			Round:     13,
			BlockID:   blk,
			POLRound:  12,
			Timestamp: cmttime.Canonical(now),
			BlobID:    blobID,
		}
		proposalProto = proposal.ToProto()
	)

	err := valStub.SignProposal(ss.ChainID, proposalProto)
	require.NoError(t, err)

	proposal.Signature = proposalProto.Signature

	var (
		walWriteBuf = new(bytes.Buffer)
		enc         = NewWALEncoder(walWriteBuf)
		twm         = TimedWALMessage{
			Time: now,
			Msg: msgInfo{
				Msg:    &ProposalMessage{Proposal: &proposal},
				PeerID: "Nobody",
			},
		}
	)
	err = enc.Encode(&twm)
	require.NoError(t, err)

	var (
		buf bytes.Buffer
		tee = io.TeeReader(walWriteBuf, &buf)
	)
	walData, err := io.ReadAll(tee)
	require.NoError(t, err)

	// fmt.Printf("%s\n", hex.EncodeToString(buf.Bytes()))

	// Encoded string generated v1.0.0 Berachain Fork
	// The hex string below is what the WAL has written to walWriteBuf.
	// You can check it by uncommenting the Printf line above.
	data, err := hex.DecodeString(
		"8059ec450000012f0a0b0880e2c3b1a4feffffff01129f02129c020a91021a8e020a8b020820102a180d200c2a480a2001c073624aaf3978514ef8443bb2a859c75fc3cc6af26d5aaa20926f046baa6612240805122001c073624aaf3978514ef8443bb2a859c75fc3cc6af26d5aaa20926f046baa66320b0880e2c3b1a4feffffff013a60b27b5c678f768fb0e6656fd151a39187772bbe4bbb684fb728d37689a8da62714bfd0956e7ab6124d7aa548fb73eab840e2830c4ef0bdf9a22669b0a9fdee332fdee6aa0617e6379000e2def2c3ea3f16b23ced8f788d87fea90aa33b1974a1742480a20ec91a5a2794323c2da405afed61ec15cf793ed103a57c02c869af069b7b56837122408051220ec91a5a2794323c2da405afed61ec15cf793ed103a57c02c869af069b7b5683712064e6f626f6479",
	)
	require.NoError(t, err)
	require.Equal(t, data, walData)
}

func TestWALWrite(t *testing.T) {
	walDir := t.TempDir()
	walFile := filepath.Join(walDir, "wal")

	wal, err := NewWAL(walFile)
	require.NoError(t, err)

	err = wal.Start()
	require.NoError(t, err)

	defer func() {
		if err := wal.Stop(); err != nil {
			t.Error(err)
		}
		// wait for the wal to finish shutting down so we
		// can safely remove the directory
		wal.Wait()
	}()

	// 1) Write returns an error if msg is too big
	msg := &BlockPartMessage{
		Height: 1,
		Round:  1,
		Part: &cmttypes.Part{
			Index: 1,
			Bytes: make([]byte, 1),
			Proof: merkle.Proof{
				Total:    1,
				Index:    1,
				LeafHash: make([]byte, maxMsgSizeBytes-30),
			},
		},
	}

	err = wal.Write(msgInfo{Msg: msg})

	// require.Error doesn't work with the conditional here
	if assert.Error(t, err) { //nolint:testifylint
		assert.Contains(t, err.Error(), "msg is too big")
	}
}

func TestWALSearchForEndHeight(t *testing.T) {
	walBody, err := WALWithNBlocks(t, 6, getConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	walFile := tempWALWithData(walBody)

	wal, err := NewWAL(walFile)
	require.NoError(t, err)
	wal.SetLogger(log.TestingLogger())

	h := int64(3)
	gr, found, err := wal.SearchForEndHeight(h, &WALSearchOptions{})
	require.NoError(t, err, "expected not to err on height %d", h)
	assert.True(t, found, "expected to find end height for %d", h)
	assert.NotNil(t, gr)
	defer gr.Close()

	dec := NewWALDecoder(gr)
	msg, err := dec.Decode()
	require.NoError(t, err, "expected to decode a message")
	rs, ok := msg.Msg.(cmttypes.EventDataRoundState)
	assert.True(t, ok, "expected message of type EventDataRoundState")
	assert.Equal(t, rs.Height, h+1, "wrong height")
}

func TestWALPeriodicSync(t *testing.T) {
	walDir := t.TempDir()
	walFile := filepath.Join(walDir, "wal")
	wal, err := NewWAL(walFile, autofile.GroupCheckDuration(1*time.Millisecond))
	require.NoError(t, err)

	wal.SetFlushInterval(walTestFlushInterval)
	wal.SetLogger(log.TestingLogger())

	// Generate some data
	err = WALGenerateNBlocks(t, wal.Group(), 5, getConfig(t))
	require.NoError(t, err)

	// We should have data in the buffer now
	assert.NotZero(t, wal.Group().Buffered())

	require.NoError(t, wal.Start())
	defer func() {
		if err := wal.Stop(); err != nil {
			t.Error(err)
		}
		wal.Wait()
	}()

	time.Sleep(walTestFlushInterval + (10 * time.Millisecond))

	// The data should have been flushed by the periodic sync
	assert.Zero(t, wal.Group().Buffered())

	h := int64(4)
	gr, found, err := wal.SearchForEndHeight(h, &WALSearchOptions{})
	require.NoError(t, err, "expected not to err on height %d", h)
	assert.True(t, found, "expected to find end height for %d", h)
	assert.NotNil(t, gr)
	if gr != nil {
		gr.Close()
	}
}

// FIXME: this helper is very similar to the one in ../../state/helpers_test.go.
func makeState(nVals int, chainID string) (sm.State, map[string]cmttypes.PrivValidator) {
	vals, privVals := test.GenesisValidatorSet(nVals)

	s, _ := sm.MakeGenesisState(&cmttypes.GenesisDoc{
		ChainID:         chainID,
		Validators:      vals,
		AppHash:         nil,
		ConsensusParams: test.ConsensusParams(),
	})

	stateDB := dbm.NewMemDB()
	stateStore := sm.NewStore(stateDB, sm.StoreOptions{
		DiscardABCIResponses: false,
	})
	if err := stateStore.Save(s); err != nil {
		panic(err)
	}

	return s, privVals
}

/*
var initOnce sync.Once

func registerInterfacesOnce() {
	initOnce.Do(func() {
		var _ = wire.RegisterInterface(
			struct{ WALMessage }{},
			wire.ConcreteType{[]byte{}, 0x10},
		)
	})
}
*/

func nBytes(n int) []byte {
	buf := make([]byte, n)
	n, _ = rand.Read(buf)
	return buf[:n]
}

func benchmarkWalDecode(b *testing.B, n int) {
	b.Helper()
	// registerInterfacesOnce()

	buf := new(bytes.Buffer)
	enc := NewWALEncoder(buf)

	data := nBytes(n)
	if err := enc.Encode(&TimedWALMessage{Msg: data, Time: cmttime.Now().Round(time.Second).UTC()}); err != nil {
		b.Error(err)
	}

	encoded := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		buf.Write(encoded)
		dec := NewWALDecoder(buf)
		if _, err := dec.Decode(); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
}

func BenchmarkWalDecode512B(b *testing.B) {
	benchmarkWalDecode(b, 512)
}

func BenchmarkWalDecode10KB(b *testing.B) {
	benchmarkWalDecode(b, 10*1024)
}

func BenchmarkWalDecode100KB(b *testing.B) {
	benchmarkWalDecode(b, 100*1024)
}

func BenchmarkWalDecode1MB(b *testing.B) {
	benchmarkWalDecode(b, 1024*1024)
}

func BenchmarkWalDecode10MB(b *testing.B) {
	benchmarkWalDecode(b, 10*1024*1024)
}

func BenchmarkWalDecode100MB(b *testing.B) {
	benchmarkWalDecode(b, 100*1024*1024)
}

func BenchmarkWalDecode1GB(b *testing.B) {
	benchmarkWalDecode(b, 1024*1024*1024)
}

// getConfig returns a config for test cases.
func getConfig(t *testing.T) *cfg.Config {
	t.Helper()
	c := test.ResetTestRoot(t.Name())

	// and we use random ports to run in parallel
	cmt, rpc := makeAddrs()
	c.P2P.ListenAddress = cmt
	c.RPC.ListenAddress = rpc
	return c
}
