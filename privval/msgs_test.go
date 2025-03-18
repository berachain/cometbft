package privval

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/require"

	privproto "github.com/cometbft/cometbft/api/cometbft/privval/v1"
	cmtproto "github.com/cometbft/cometbft/api/cometbft/types/v1"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
	"github.com/cometbft/cometbft/types"
)

var stamp = time.Date(2019, 10, 13, 16, 14, 44, 0, time.UTC)

func exampleVote() *types.Vote {
	return &types.Vote{
		Type:             types.PrecommitType,
		Height:           3,
		Round:            2,
		BlockID:          types.BlockID{Hash: tmhash.Sum([]byte("blockID_hash")), PartSetHeader: types.PartSetHeader{Total: 1000000, Hash: tmhash.Sum([]byte("blockID_part_set_header_hash"))}},
		ValidatorAddress: crypto.AddressHash([]byte("validator_address")),
		ValidatorIndex:   56789,
		Extension:        []byte("extension"),
	}
}

func exampleProposal() *types.Proposal {
	return &types.Proposal{
		Type:      types.SignedMsgType(1),
		Height:    3,
		Round:     2,
		Timestamp: stamp,
		POLRound:  2,
		Signature: []byte("it's a signature"),
		BlockID: types.BlockID{
			Hash: tmhash.Sum([]byte("blockID_hash")),
			PartSetHeader: types.PartSetHeader{
				Total: 1000000,
				Hash:  tmhash.Sum([]byte("blockID_part_set_header_hash")),
			},
		},
		BlobID: types.BlobID{},
	}
}

//nolint:lll // ignore line length for tests
func TestPrivvalVectors(t *testing.T) {
	var (
		pk = ed25519.GenPrivKeyFromSecret([]byte("it's a secret")).PubKey()

		// Generate a simple vote
		vote   = exampleVote()
		votepb = vote.ToProto()

		// Generate a simple proposal
		proposal   = exampleProposal()
		proposalpb = proposal.ToProto()

		// Create a reusable remote error
		remoteError = &privproto.RemoteSignerError{
			Code:        1,
			Description: "it's a error",
		}

		testCases = []struct {
			name string
			msg  proto.Message

			// hex-encoded string of the serialized privproto.Message wrapping msg
			expBytes string
		}{
			{"ping request", &privproto.PingRequest{}, "3a00"},
			{"ping response", &privproto.PingResponse{}, "4200"},
			{"pubKey request", &privproto.PubKeyRequest{}, "0a00"},
			{
				name: "pubKey response",
				msg: &privproto.PubKeyResponse{
					PubKeyType:  pk.Type(),
					PubKeyBytes: pk.Bytes(),
					Error:       nil,
				},
				expBytes: "122b1a20556a436f1218d30942efe798420f51dc9b6a311b929c578257457d05c5fcf230220765643235353139",
			},
			{
				name: "pubKey response with error",
				msg: &privproto.PubKeyResponse{
					PubKeyType:  "",
					PubKeyBytes: []byte{},
					Error:       remoteError,
				},
				expBytes: "121212100801120c697427732061206572726f72",
			},
			{
				name:     "Vote Request",
				msg:      &privproto.SignVoteRequest{Vote: votepb},
				expBytes: "1a87010a8401080210031802224a0a208b01023386c371778ecb6368573e539afc3cc860ec3a2f614e54fe5652f4fc80122608c0843d122072db3d959635dff1bb567bedaa70573392c5159666a3f8caf11e413aac52207a2a0b088092b8c398feffffff0132146af1f4111082efb388211bc72c55bcd61e9ac3d538d5bb034a09657874656e73696f6e",
			},
			{
				name: "Vote Response",
				msg:  &privproto.SignedVoteResponse{Vote: *votepb, Error: nil}, expBytes: "2287010a8401080210031802224a0a208b01023386c371778ecb6368573e539afc3cc860ec3a2f614e54fe5652f4fc80122608c0843d122072db3d959635dff1bb567bedaa70573392c5159666a3f8caf11e413aac52207a2a0b088092b8c398feffffff0132146af1f4111082efb388211bc72c55bcd61e9ac3d538d5bb034a09657874656e73696f6e",
			},
			{
				name: "Vote Response with error",
				msg: &privproto.SignedVoteResponse{
					Vote:  cmtproto.Vote{},
					Error: remoteError,
				},
				expBytes: "22250a11220212002a0b088092b8c398feffffff0112100801120c697427732061206572726f72",
			},
			{
				name:     "Proposal Request",
				msg:      &privproto.SignProposalRequest{Proposal: proposalpb},
				expBytes: "2a740a7208011003180220022a4a0a208b01023386c371778ecb6368573e539afc3cc860ec3a2f614e54fe5652f4fc80122608c0843d122072db3d959635dff1bb567bedaa70573392c5159666a3f8caf11e413aac52207a320608f49a8ded053a10697427732061207369676e617475726542021200",
			},
			{
				name: "Proposal Response",
				msg: &privproto.SignedProposalResponse{
					Proposal: *proposalpb,
					Error:    nil,
				},
				expBytes: "32740a7208011003180220022a4a0a208b01023386c371778ecb6368573e539afc3cc860ec3a2f614e54fe5652f4fc80122608c0843d122072db3d959635dff1bb567bedaa70573392c5159666a3f8caf11e413aac52207a320608f49a8ded053a10697427732061207369676e617475726542021200",
			},
			{
				name: "Proposal Response with error",
				msg: &privproto.SignedProposalResponse{
					Proposal: cmtproto.Proposal{},
					Error:    remoteError,
				},
				expBytes: "32290a152a021200320b088092b8c398feffffff014202120012100801120c697427732061206572726f72",
			},
		}
	)

	for _, tc := range testCases {
		pm := mustWrapMsg(tc.msg)

		bz, err := pm.Marshal()
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.expBytes, hex.EncodeToString(bz), tc.name)
	}
}
