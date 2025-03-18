package types

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmtproto "github.com/cometbft/cometbft/api/cometbft/types/v1"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtrand "github.com/cometbft/cometbft/internal/rand"
	"github.com/cometbft/cometbft/libs/protoio"
	cmttime "github.com/cometbft/cometbft/types/time"
)

var (
	testProposal      *Proposal
	testBlockID       BlockID
	testBlobID        BlobID
	testProtoProposal *cmtproto.Proposal
)

func init() {
	stamp, err := time.Parse(TimeFormat, "2018-02-11T07:09:22.765Z")
	if err != nil {
		panic(err)
	}

	testBlockID = BlockID{
		Hash: []byte("--June_15_2020_amino_was_removed"),
		PartSetHeader: PartSetHeader{
			Total: 111,
			Hash:  []byte("--June_15_2020_amino_was_removed"),
		},
	}

	testBlobID = BlobID{
		Hash: []byte("-this_blob_id_hash_is_32_bytes--"),
		PartSetHeader: PartSetHeader{
			Total: 42,
			Hash: []byte(
				"--this_header_hash_is_32_bytes--"),
		},
	}

	testProposal = &Proposal{
		Type:      ProposalType,
		Height:    12345,
		Round:     23456,
		BlockID:   testBlockID,
		POLRound:  -1,
		Timestamp: stamp,
		BlobID:    testBlobID,
	}

	testProtoProposal = testProposal.ToProto()
}

func TestProposalSignable(t *testing.T) {
	chainID := "test_chain_id"
	signBytes := ProposalSignBytes(chainID, testProtoProposal)
	pb := CanonicalizeProposal(chainID, testProtoProposal)

	expected, err := protoio.MarshalDelimited(&pb)
	require.NoError(t, err)
	require.Equal(t, expected, signBytes, "Got unexpected sign bytes for Proposal")
}

func TestProposalString(t *testing.T) {
	str := testProposal.String()
	expected := `Proposal{12345/23456 (2D2D4A756E655F31355F323032305F616D696E6F5F7761735F72656D6F766564:111:2D2D4A756E65, -1) (2D746869735F626C6F625F69645F686173685F69735F33325F62797465732D2D:42:2D2D74686973) 000000000000 @ 2018-02-11T07:09:22.765Z}` //nolint:lll // ignore line length for tests
	if str != expected {
		t.Errorf("got unexpected string for Proposal. Expected:\n%v\nGot:\n%v", expected, str)
	}
}

func TestProposalVerifySignature(t *testing.T) {
	privVal := NewMockPV()
	pubKey, err := privVal.GetPubKey()
	require.NoError(t, err)

	var (
		blockID = BlockID{
			Hash:          cmtrand.Bytes(tmhash.Size),
			PartSetHeader: PartSetHeader{777, cmtrand.Bytes(tmhash.Size)},
		}
		blobID = BlobID{
			Hash:          cmtrand.Bytes(tmhash.Size),
			PartSetHeader: PartSetHeader{42, cmtrand.Bytes(tmhash.Size)},
		}
		proposal = NewProposal(
			4, /* height */
			2, /* round */
			1, /* polRound */
			blockID,
			cmttime.Now(),
			blobID,
		)
		protoProposal = proposal.ToProto()
		signBytes     = ProposalSignBytes("test_chain_id", protoProposal)
	)

	// sign it
	err = privVal.SignProposal("test_chain_id", protoProposal)
	require.NoError(t, err)

	proposal.Signature = protoProposal.Signature

	// verify the same proposal
	valid := pubKey.VerifySignature(signBytes, proposal.Signature)
	require.True(t, valid)

	// serialize, deserialize and verify again....
	newProp := new(cmtproto.Proposal)
	pb := proposal.ToProto()

	bs, err := proto.Marshal(pb)
	require.NoError(t, err)

	err = proto.Unmarshal(bs, newProp)
	require.NoError(t, err)

	np, err := ProposalFromProto(newProp)
	require.NoError(t, err)

	// verify the transmitted proposal
	newSignBytes := ProposalSignBytes("test_chain_id", pb)
	require.Equal(t, string(signBytes), string(newSignBytes))
	valid = pubKey.VerifySignature(newSignBytes, np.Signature)
	require.True(t, valid)
}

func BenchmarkProposalWriteSignBytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ProposalSignBytes("test_chain_id", testProtoProposal)
	}
}

func BenchmarkProposalSign(b *testing.B) {
	privVal := NewMockPV()
	for i := 0; i < b.N; i++ {
		err := privVal.SignProposal("test_chain_id", testProtoProposal)
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkProposalVerifySignature(b *testing.B) {
	privVal := NewMockPV()
	err := privVal.SignProposal("test_chain_id", testProtoProposal)
	require.NoError(b, err)
	pubKey, err := privVal.GetPubKey()
	require.NoError(b, err)

	for i := 0; i < b.N; i++ {
		pubKey.VerifySignature(ProposalSignBytes("test_chain_id", testProtoProposal), testProposal.Signature)
	}
}

func TestProposalValidateBasic(t *testing.T) {
	location, err := time.LoadLocation("CET")
	require.NoError(t, err)

	var (
		testCases = []struct {
			name         string
			malleateFunc func(*Proposal)
			expectErr    bool
		}{
			{"GoodProposal", func(*Proposal) {}, false},
			{
				name: "TestProposal",
				malleateFunc: func(p *Proposal) {
					p.Type = testProposal.Type
					p.Height = testProposal.Height
					p.Round = testProposal.Round
					p.BlockID = testProposal.BlockID
					p.POLRound = testProposal.POLRound
					p.Timestamp = testProposal.Timestamp
					p.BlobID = testProposal.BlobID
				},
				expectErr: false,
			},
			{"InvalidType", func(p *Proposal) { p.Type = PrecommitType }, true},
			{"InvalidHeight", func(p *Proposal) { p.Height = -1 }, true},
			{"ZeroHeight", func(p *Proposal) { p.Height = 0 }, true},
			{"InvalidRound", func(p *Proposal) { p.Round = -1 }, true},
			{"InvalidPOLRound", func(p *Proposal) { p.POLRound = -2 }, true},
			{"POLRound==Round", func(p *Proposal) { p.POLRound = p.Round }, true},
			{
				name: "InvalidBlockID",
				malleateFunc: func(p *Proposal) {
					p.BlockID = BlockID{
						Hash: []byte{1, 2, 3},
						PartSetHeader: PartSetHeader{
							Total: 111,
							Hash:  []byte("blockparts"),
						},
					}
				},
				expectErr: true,
			},
			{
				name:         "InvalidSignature",
				malleateFunc: func(p *Proposal) { p.Signature = make([]byte, 0) },
				expectErr:    true,
			},
			{
				name: "SmallSignature",
				malleateFunc: func(p *Proposal) {
					p.Signature = make([]byte, MaxSignatureSize-1)
				},
				expectErr: false,
			},
			{
				name: "TooBigSignature",
				malleateFunc: func(p *Proposal) {
					p.Signature = make([]byte, MaxSignatureSize+1)
				},
				expectErr: true,
			},
			{
				name: "NonCanonicalTime",
				malleateFunc: func(p *Proposal) {
					p.Timestamp = time.Now().In(location)
				},
				expectErr: true,
			},
			{
				name:         "Not rounded time",
				malleateFunc: func(p *Proposal) { p.Timestamp = time.Now() },
				expectErr:    true,
			},
		}
		privVal = NewMockPV()
		blockID = makeBlockID(
			tmhash.Sum([]byte("blockhash")),
			math.MaxInt32,
			tmhash.Sum([]byte("partshash")),
		)
		blobID = mockBlobID(
			tmhash.Sum([]byte("blobhash")),
			math.MaxInt32,
			tmhash.Sum([]byte("partshash")),
		)
	)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			prop := NewProposal(
				4, /* height */
				2, /* round */
				1, /* polRound */
				blockID,
				cmttime.Now(),
				blobID,
			)
			protoProposal := prop.ToProto()

			err := privVal.SignProposal("test_chain_id", protoProposal)
			prop.Signature = protoProposal.Signature
			require.NoError(t, err)

			tc.malleateFunc(prop)

			err = prop.ValidateBasic()
			errMsg := fmt.Sprintf("Validate Basic had an unexpected error: %v", err)
			assert.Equal(t, tc.expectErr, prop.ValidateBasic() != nil, errMsg)
		})
	}
}

func TestProposalProtoBuf(t *testing.T) {
	var (
		blockID  = makeBlockID([]byte("hash"), 2, []byte("part_set_hash"))
		blobID   = mockBlobID([]byte("hash"), 4, []byte("part_set_hash"))
		proposal = NewProposal(
			1, /* height */
			2, /* round */
			1, /* polRound */
			blockID,
			cmttime.Now(),
			blobID,
		)
	)
	proposal.Signature = []byte("sig")

	var (
		proposal2 = NewProposal(
			1, /* height */
			2, /* round */
			1, /* polRound */
			BlockID{},
			cmttime.Now(),
			BlobID{},
		)
		testCases = []struct {
			name     string
			proposal *Proposal
			expPass  bool
		}{
			{"Success", proposal, true},
			{"Success", proposal2, false}, // blockID cannot be empty
			{"EmptyProposalFailureValidateBasic", &Proposal{}, false},
			{"NilProposal", nil, false},
		}
	)
	for _, tc := range testCases {
		protoProposal := tc.proposal.ToProto()

		gotProposal, err := ProposalFromProto(protoProposal)
		if tc.expPass {
			require.NoError(t, err)
			require.Equal(t, tc.proposal, gotProposal, tc.name)
		} else {
			require.Error(t, err)
		}
	}
}

func TestProposalIsTimely(t *testing.T) {
	timestamp, err := time.Parse(time.RFC3339, "2019-03-13T23:00:00Z")
	require.NoError(t, err)
	sp := SynchronyParams{
		Precision:    time.Nanosecond,
		MessageDelay: 2 * time.Nanosecond,
	}
	testCases := []struct {
		name                string
		proposalHeight      int64
		proposalTimestamp   time.Time
		proposalReceiveTime time.Time
		expectTimely        bool
	}{
		// Timely requirements:
		// proposalReceiveTime >= proposalTimestamp - PRECISION
		// proposalReceiveTime <= proposalTimestamp + MSGDELAY + PRECISION
		{
			name:                "timestamp in the past",
			proposalHeight:      2,
			proposalTimestamp:   timestamp,
			proposalReceiveTime: timestamp.Add(sp.Precision + sp.MessageDelay),
			expectTimely:        true,
		},
		{
			name:                "timestamp far in the past",
			proposalHeight:      2,
			proposalTimestamp:   timestamp,
			proposalReceiveTime: timestamp.Add(sp.Precision + sp.MessageDelay + 1),
			expectTimely:        false,
		},
		{
			name:                "timestamp in the future",
			proposalHeight:      2,
			proposalTimestamp:   timestamp.Add(sp.Precision),
			proposalReceiveTime: timestamp,
			expectTimely:        true,
		},
		{
			name:                "timestamp far in the future",
			proposalHeight:      2,
			proposalTimestamp:   timestamp.Add(sp.Precision + 1),
			proposalReceiveTime: timestamp,
			expectTimely:        false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			p := Proposal{
				Type:      ProposalType,
				Height:    testCase.proposalHeight,
				Timestamp: testCase.proposalTimestamp,
				Round:     0,
				POLRound:  -1,
				BlockID:   testBlockID,
				Signature: []byte{1},
			}
			require.NoError(t, p.ValidateBasic())

			ti := p.IsTimely(testCase.proposalReceiveTime, sp)
			assert.Equal(t, testCase.expectTimely, ti)
		})
	}
}

func TestProposalIsTimelyOverflow(t *testing.T) {
	sp := DefaultSynchronyParams()
	lastSP := sp
	var overflowRound int32
	var overflowMessageDelay time.Duration
	// Exponentially increase rounds to find when it overflows
	for round := int32(1); round > 0; /* no overflow */ round *= 2 {
		adaptedSP := sp.InRound(round)
		if adaptedSP.MessageDelay == lastSP.MessageDelay { // overflow
			overflowRound = round / 2
			overflowMessageDelay = lastSP.MessageDelay
			break
		}
		lastSP = adaptedSP
	}

	// Linearly search for the exact overflow round
	for round := overflowRound / 2; round <= overflowRound; round++ {
		adaptedSP := sp.InRound(round)
		if adaptedSP.MessageDelay == overflowMessageDelay {
			overflowRound = round
			break
		}
	}

	sp = sp.InRound(overflowRound)
	t.Log("Overflow round", overflowRound, "MessageDelay", sp.MessageDelay)

	timestamp, err := time.Parse(time.RFC3339, "2019-03-13T23:00:00Z")
	require.NoError(t, err)

	p := Proposal{
		Type:      ProposalType,
		Height:    2,
		Timestamp: timestamp,
		Round:     0,
		POLRound:  -1,
		BlockID:   testBlockID,
		Signature: []byte{1},
	}
	require.NoError(t, p.ValidateBasic())

	// Timestamp a bit in the future
	proposalReceiveTime := timestamp.Add(-sp.Precision)
	assert.True(t, p.IsTimely(proposalReceiveTime, sp))

	// Timestamp far in the future is still rejected
	proposalReceiveTime = timestamp.Add(-sp.Precision).Add(-1)
	assert.False(t, p.IsTimely(proposalReceiveTime, sp))

	// Receive time as in the future as it can get
	proposalReceiveTime = timestamp.Add(sp.MessageDelay).Add(sp.Precision)
	assert.True(t, p.IsTimely(proposalReceiveTime, sp))

	// Timestamp as in the past as it can get
	proposalReceiveTime = timestamp
	p.Timestamp = timestamp.Add(-sp.MessageDelay).Add(-sp.Precision)
	assert.True(t, p.IsTimely(proposalReceiveTime, sp))
}
