package consensus

import (
	"encoding/hex"
	"math"
	"testing"
	"time"

	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmtcons "github.com/cometbft/cometbft/api/cometbft/consensus/v1"
	cmtproto "github.com/cometbft/cometbft/api/cometbft/types/v1"
	"github.com/cometbft/cometbft/crypto/merkle"
	"github.com/cometbft/cometbft/internal/bits"
	cmtrand "github.com/cometbft/cometbft/internal/rand"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/types"
	cmttime "github.com/cometbft/cometbft/types/time"
)

func TestMsgToProto(t *testing.T) {
	var (
		blkPartSetHdr = types.PartSetHeader{
			Total: 1,
			Hash:  cmtrand.Bytes(32),
		}
		protoBlkPartSetHdr = blkPartSetHdr.ToProto()
		blkPart            = types.Part{
			Index: 1,
			Bytes: []byte("test"),
			Proof: merkle.Proof{
				Total:    1,
				Index:    1,
				LeafHash: cmtrand.Bytes(32),
				Aunts:    [][]byte{},
			},
		}
		blkID = types.BlockID{
			Hash:          cmtrand.Bytes(32),
			PartSetHeader: blkPartSetHdr,
		}
		protoBlkID = blkID.ToProto()

		blobPartSetHdr = types.PartSetHeader{
			Total: 1,
			Hash:  cmtrand.Bytes(32),
		}
		blobPart = types.Part{
			Index: 1,
			Bytes: []byte("blob"),
			Proof: merkle.Proof{
				Total:    1,
				Index:    1,
				LeafHash: cmtrand.Bytes(32),
				Aunts:    [][]byte{},
			},
		}
		blobID = types.BlobID{
			Hash:          cmtrand.Bytes(32),
			PartSetHeader: blobPartSetHdr,
		}

		proposal = types.Proposal{
			Type:      types.ProposalType,
			Height:    1,
			Round:     2,
			POLRound:  1,
			BlockID:   blkID,
			BlobID:    blobID,
			Timestamp: cmttime.Now(),
			Signature: cmtrand.Bytes(20),
		}
		protoProposal = proposal.ToProto()
		vote          = types.MakeVoteNoError(
			t,
			types.NewMockPV(),
			"chainID",
			0, /* valIndex */
			1, /* height */
			0, /* round */
			types.PrecommitType,
			blkID,
			cmttime.Now(),
		)
		protoVote = vote.ToProto()
		bits      = bits.NewBitArray(1)
		protoBits = bits.ToProto()
	)
	protoBlkPart, err := blkPart.ToProto()
	require.NoError(t, err)

	protoBlobPart, err := blobPart.ToProto()
	require.NoError(t, err)

	testsCases := []struct {
		name         string
		msg          Message
		wantProtoMsg proto.Message
		wantErr      bool
	}{
		{
			name: "successful NewRoundStepMessage",
			msg: &NewRoundStepMessage{
				Height:                2,
				Round:                 1,
				Step:                  1,
				SecondsSinceStartTime: 1,
				LastCommitRound:       2,
			},
			wantProtoMsg: &cmtcons.NewRoundStep{
				Height:                2,
				Round:                 1,
				Step:                  1,
				SecondsSinceStartTime: 1,
				LastCommitRound:       2,
			},
			wantErr: false,
		},
		{
			name: "successful NewValidBlockMessage",
			msg: &NewValidBlockMessage{
				Height:             1,
				Round:              1,
				BlockPartSetHeader: blkPartSetHdr,
				BlockParts:         bits,
				IsCommit:           false,
			},
			wantProtoMsg: &cmtcons.NewValidBlock{
				Height:             1,
				Round:              1,
				BlockPartSetHeader: protoBlkPartSetHdr,
				BlockParts:         protoBits,
				IsCommit:           false,
			},
			wantErr: false,
		},
		{
			name: "successful BlockPartMessage",
			msg: &BlockPartMessage{
				Height: 100,
				Round:  1,
				Part:   &blkPart,
			},
			wantProtoMsg: &cmtcons.BlockPart{
				Height: 100,
				Round:  1,
				Part:   *protoBlkPart,
			},
			wantErr: false,
		},
		{
			name: "successful ProposalPOLMessage",
			msg: &ProposalPOLMessage{
				Height:           1,
				ProposalPOLRound: 1,
				ProposalPOL:      bits,
			},
			wantProtoMsg: &cmtcons.ProposalPOL{
				Height:           1,
				ProposalPolRound: 1,
				ProposalPol:      *protoBits,
			},
			wantErr: false,
		},
		{
			name: "successful ProposalMessage",
			msg: &ProposalMessage{
				Proposal: &proposal,
			},
			wantProtoMsg: &cmtcons.Proposal{
				Proposal: *protoProposal,
			},
			wantErr: false,
		},
		{
			name: "successful VoteMessage",
			msg: &VoteMessage{
				Vote: vote,
			},
			wantProtoMsg: &cmtcons.Vote{
				Vote: protoVote,
			},
			wantErr: false,
		},
		{
			name: "successful VoteSetMaj23",
			msg: &VoteSetMaj23Message{
				Height:  1,
				Round:   1,
				Type:    1,
				BlockID: blkID,
			},
			wantProtoMsg: &cmtcons.VoteSetMaj23{
				Height:  1,
				Round:   1,
				Type:    1,
				BlockID: protoBlkID,
			},
			wantErr: false,
		},
		{
			name: "successful VoteSetBits",
			msg: &VoteSetBitsMessage{
				Height:  1,
				Round:   1,
				Type:    1,
				BlockID: blkID,
				Votes:   bits,
			},
			wantProtoMsg: &cmtcons.VoteSetBits{
				Height:  1,
				Round:   1,
				Type:    1,
				BlockID: protoBlkID,
				Votes:   *protoBits,
			},
			wantErr: false,
		},
		{
			name: "successful BlobPartMessage",
			msg: &BlobPartMessage{
				Height: 42,
				Round:  1,
				Part:   &blobPart,
			},
			wantProtoMsg: &cmtcons.BlobPart{
				Height: 42,
				Round:  1,
				Part:   *protoBlobPart,
			},
			wantErr: false,
		},
		{
			name:         "failure",
			msg:          nil,
			wantProtoMsg: &cmtcons.Message{},
			wantErr:      true,
		},
	}
	for _, tt := range testsCases {
		t.Run(tt.name, func(t *testing.T) {
			wrappedProto, err := MsgToWrappedProto(tt.msg)
			if tt.wantErr {
				assert.Equal(t, tt.wantErr, err != nil)
				return
			}
			require.NoError(t, err)

			gotProtoMsg, err := wrappedProto.Unwrap()
			require.NoError(t, err)

			assert.EqualValues(t, tt.wantProtoMsg, gotProtoMsg, tt.name)

			gotMsg, err := MsgFromProto(gotProtoMsg)
			if !tt.wantErr {
				require.NoError(t, err)
				bcm := assert.Equal(t, tt.msg, gotMsg, tt.name)
				assert.True(t, bcm, tt.name)
			} else {
				require.Error(t, err, tt.name)
			}
		})
	}
}

func TestWALMsgProto(t *testing.T) {
	parts := types.Part{
		Index: 1,
		Bytes: []byte("test"),
		Proof: merkle.Proof{
			Total:    1,
			Index:    1,
			LeafHash: cmtrand.Bytes(32),
			Aunts:    [][]byte{},
		},
	}
	pbParts, err := parts.ToProto()
	require.NoError(t, err)
	now := cmttime.Now()

	testsCases := []struct {
		testName    string
		msg         WALMessage
		want        *cmtcons.WALMessage
		wantErr     bool
		equalValues bool // False for msgInfo, since equalValues does not see nil and time{} as equivalent
	}{
		{"successful EventDataRoundState", types.EventDataRoundState{
			Height: 2,
			Round:  1,
			Step:   "ronies",
		}, &cmtcons.WALMessage{
			Sum: &cmtcons.WALMessage_EventDataRoundState{
				EventDataRoundState: &cmtproto.EventDataRoundState{
					Height: 2,
					Round:  1,
					Step:   "ronies",
				},
			},
		}, false, true},
		{"successful msgInfo", msgInfo{
			Msg: &BlockPartMessage{
				Height: 100,
				Round:  1,
				Part:   &parts,
			},
			PeerID: p2p.ID("string"),
		}, &cmtcons.WALMessage{
			Sum: &cmtcons.WALMessage_MsgInfo{
				MsgInfo: &cmtcons.MsgInfo{
					Msg: cmtcons.Message{
						Sum: &cmtcons.Message_BlockPart{
							BlockPart: &cmtcons.BlockPart{
								Height: 100,
								Round:  1,
								Part:   *pbParts,
							},
						},
					},
					PeerID: "string",
				},
			},
		}, false, false},
		{"successful msgInfo with receive time", msgInfo{
			Msg: &BlockPartMessage{
				Height: 100,
				Round:  1,
				Part:   &parts,
			},
			PeerID: p2p.ID("string"),
		}, &cmtcons.WALMessage{
			Sum: &cmtcons.WALMessage_MsgInfo{
				MsgInfo: &cmtcons.MsgInfo{
					Msg: cmtcons.Message{
						Sum: &cmtcons.Message_BlockPart{
							BlockPart: &cmtcons.BlockPart{
								Height: 100,
								Round:  1,
								Part:   *pbParts,
							},
						},
					},
					PeerID:      "string",
					ReceiveTime: &time.Time{},
				},
			},
		}, false, false},
		{"successful msgInfo with receive time explicit", msgInfo{
			Msg: &BlockPartMessage{
				Height: 100,
				Round:  1,
				Part:   &parts,
			},
			PeerID: p2p.ID("string"),
		}, &cmtcons.WALMessage{
			Sum: &cmtcons.WALMessage_MsgInfo{
				MsgInfo: &cmtcons.MsgInfo{
					Msg: cmtcons.Message{
						Sum: &cmtcons.Message_BlockPart{
							BlockPart: &cmtcons.BlockPart{
								Height: 100,
								Round:  1,
								Part:   *pbParts,
							},
						},
					},
					PeerID:      "string",
					ReceiveTime: &now,
				},
			},
		}, false, false},
		{"successful timeoutInfo", timeoutInfo{
			Duration: time.Duration(100),
			Height:   1,
			Round:    1,
			Step:     1,
		}, &cmtcons.WALMessage{
			Sum: &cmtcons.WALMessage_TimeoutInfo{
				TimeoutInfo: &cmtcons.TimeoutInfo{
					Duration: time.Duration(100),
					Height:   1,
					Round:    1,
					Step:     1,
				},
			},
		}, false, true},
		{"successful EndHeightMessage", EndHeightMessage{
			Height: 1,
		}, &cmtcons.WALMessage{
			Sum: &cmtcons.WALMessage_EndHeight{
				EndHeight: &cmtcons.EndHeight{
					Height: 1,
				},
			},
		}, false, true},
		{"failure", nil, &cmtcons.WALMessage{}, true, true},
	}
	for _, tt := range testsCases {
		t.Run(tt.testName, func(t *testing.T) {
			pb, err := WALToProto(tt.msg)
			if tt.wantErr {
				assert.Equal(t, tt.wantErr, err != nil)
				return
			}

			if tt.equalValues {
				assert.EqualValues(t, tt.want, pb, tt.testName)
			}

			msg, err := WALFromProto(pb)

			if !tt.wantErr {
				require.NoError(t, err)
				assert.Equal(t, tt.msg, msg, tt.testName) // need the concrete type as WAL Message is a empty interface
			} else {
				require.Error(t, err, tt.testName)
			}
		})
	}
}

//nolint:lll //ignore line length for tests
func TestConsMsgsVectors(t *testing.T) {
	var (
		date = time.Date(2018, 8, 30, 12, 0, 0, 0, time.UTC)
		psh  = types.PartSetHeader{
			Total: 1,
			Hash:  []byte("add_more_exclamation_marks_code-"),
		}
		pbPsh = psh.ToProto()
		bi    = types.BlockID{
			Hash:          []byte("add_more_exclamation_marks_code-"),
			PartSetHeader: psh,
		}
		pbBi   = bi.ToProto()
		bits   = bits.NewBitArray(1)
		pbBits = bits.ToProto()
		parts  = types.Part{
			Index: 1,
			Bytes: []byte("test"),
			Proof: merkle.Proof{
				Total:    1,
				Index:    1,
				LeafHash: []byte("add_more_exclamation_marks_code-"),
				Aunts:    [][]byte{},
			},
		}
	)

	pbParts, err := parts.ToProto()
	require.NoError(t, err)

	var (
		proposal = types.Proposal{
			Type:      types.ProposalType,
			Height:    1,
			Round:     1,
			POLRound:  1,
			BlockID:   bi,
			Timestamp: date,
			Signature: []byte("add_more_exclamation"),
			BlobID:    types.BlobID{},
		}
		pbProposal = proposal.ToProto()
		v          = &types.Vote{
			ValidatorAddress: []byte("add_more_exclamation"),
			ValidatorIndex:   1,
			Height:           1,
			Round:            0,
			Type:             types.PrecommitType,
			BlockID:          bi,
		}
		vpb = v.ToProto()
	)

	v.Extension = []byte("extension")

	var (
		vextPb = v.ToProto()

		testCases = []struct {
			name         string
			consensusMsg proto.Message

			// hex-encoded string of the consensusMsg serialized to protobuf.
			wantBytes string
		}{
			{
				name: "NewRoundStep",
				consensusMsg: &cmtcons.Message{
					Sum: &cmtcons.Message_NewRoundStep{
						NewRoundStep: &cmtcons.NewRoundStep{
							Height:                1,
							Round:                 1,
							Step:                  1,
							SecondsSinceStartTime: 1,
							LastCommitRound:       1,
						},
					},
				},
				wantBytes: "0a0a08011001180120012801",
			},
			{
				name: "NewRoundStepMax",
				consensusMsg: &cmtcons.Message{
					Sum: &cmtcons.Message_NewRoundStep{
						NewRoundStep: &cmtcons.NewRoundStep{
							Height:                math.MaxInt64,
							Round:                 math.MaxInt32,
							Step:                  math.MaxUint32,
							SecondsSinceStartTime: math.MaxInt64,
							LastCommitRound:       math.MaxInt32,
						},
					},
				},
				wantBytes: "0a2608ffffffffffffffff7f10ffffffff0718ffffffff0f20ffffffffffffffff7f28ffffffff07",
			},
			{
				name: "NewValidBlock",
				consensusMsg: &cmtcons.Message{
					Sum: &cmtcons.Message_NewValidBlock{
						NewValidBlock: &cmtcons.NewValidBlock{
							Height:             1,
							Round:              1,
							BlockPartSetHeader: pbPsh,
							BlockParts:         pbBits,
							IsCommit:           false,
						},
					},
				},
				wantBytes: "1231080110011a24080112206164645f6d6f72655f6578636c616d6174696f6e5f6d61726b735f636f64652d22050801120100",
			},
			{
				name: "Proposal",
				consensusMsg: &cmtcons.Message{
					Sum: &cmtcons.Message_Proposal{
						Proposal: &cmtcons.Proposal{Proposal: *pbProposal},
					},
				},
				wantBytes: "1a760a7408201001180120012a480a206164645f6d6f72655f6578636c616d6174696f6e5f6d61726b735f636f64652d1224080112206164645f6d6f72655f6578636c616d6174696f6e5f6d61726b735f636f64652d320608c0b89fdc053a146164645f6d6f72655f6578636c616d6174696f6e42021200",
			},
			{
				name: "ProposalPol",
				consensusMsg: &cmtcons.Message{
					Sum: &cmtcons.Message_ProposalPol{
						ProposalPol: &cmtcons.ProposalPOL{
							Height:           1,
							ProposalPolRound: 1,
						},
					},
				},
				wantBytes: "2206080110011a00",
			},
			{
				name: "BlockPart",
				consensusMsg: &cmtcons.Message{
					Sum: &cmtcons.Message_BlockPart{
						BlockPart: &cmtcons.BlockPart{
							Height: 1,
							Round:  1,
							Part:   *pbParts,
						},
					},
				},
				wantBytes: "2a36080110011a3008011204746573741a26080110011a206164645f6d6f72655f6578636c616d6174696f6e5f6d61726b735f636f64652d",
			},
			{
				name: "Vote_without_ext",
				consensusMsg: &cmtcons.Message{
					Sum: &cmtcons.Message_Vote{
						Vote: &cmtcons.Vote{Vote: vpb},
					},
				},
				wantBytes: "32750a730802100122480a206164645f6d6f72655f6578636c616d6174696f6e5f6d61726b735f636f64652d1224080112206164645f6d6f72655f6578636c616d6174696f6e5f6d61726b735f636f64652d2a0b088092b8c398feffffff0132146164645f6d6f72655f6578636c616d6174696f6e3801",
			},
			{
				name: "Vote_with_ext",
				consensusMsg: &cmtcons.Message{
					Sum: &cmtcons.Message_Vote{
						Vote: &cmtcons.Vote{Vote: vextPb},
					},
				},
				wantBytes: "3280010a7e0802100122480a206164645f6d6f72655f6578636c616d6174696f6e5f6d61726b735f636f64652d1224080112206164645f6d6f72655f6578636c616d6174696f6e5f6d61726b735f636f64652d2a0b088092b8c398feffffff0132146164645f6d6f72655f6578636c616d6174696f6e38014a09657874656e73696f6e",
			},
			{
				name: "HasVote",
				consensusMsg: &cmtcons.Message{
					Sum: &cmtcons.Message_HasVote{
						HasVote: &cmtcons.HasVote{
							Height: 1,
							Round:  1,
							Type:   types.PrevoteType,
							Index:  1,
						},
					},
				},
				wantBytes: "3a080801100118012001",
			},
			{
				name: "HasVote",
				consensusMsg: &cmtcons.Message{
					Sum: &cmtcons.Message_HasVote{
						HasVote: &cmtcons.HasVote{
							Height: math.MaxInt64,
							Round:  math.MaxInt32,
							Type:   types.PrevoteType,
							Index:  math.MaxInt32,
						},
					},
				},
				wantBytes: "3a1808ffffffffffffffff7f10ffffffff07180120ffffffff07",
			},
			{
				name: "VoteSetMaj23",
				consensusMsg: &cmtcons.Message{
					Sum: &cmtcons.Message_VoteSetMaj23{
						VoteSetMaj23: &cmtcons.VoteSetMaj23{
							Height:  1,
							Round:   1,
							Type:    types.PrevoteType,
							BlockID: pbBi,
						},
					},
				},
				wantBytes: "425008011001180122480a206164645f6d6f72655f6578636c616d6174696f6e5f6d61726b735f636f64652d1224080112206164645f6d6f72655f6578636c616d6174696f6e5f6d61726b735f636f64652d",
			},
			{
				name: "VoteSetBits",
				consensusMsg: &cmtcons.Message{
					Sum: &cmtcons.Message_VoteSetBits{
						VoteSetBits: &cmtcons.VoteSetBits{
							Height:  1,
							Round:   1,
							Type:    types.PrevoteType,
							BlockID: pbBi,
							Votes:   *pbBits,
						},
					},
				},
				wantBytes: "4a5708011001180122480a206164645f6d6f72655f6578636c616d6174696f6e5f6d61726b735f636f64652d1224080112206164645f6d6f72655f6578636c616d6174696f6e5f6d61726b735f636f64652d2a050801120100",
			},
		}
	)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bz, err := proto.Marshal(tc.consensusMsg)
			require.NoError(t, err)

			require.Equal(t, tc.wantBytes, hex.EncodeToString(bz))
		})
	}
}
