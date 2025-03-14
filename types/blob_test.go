package types

import (
	"testing"

	cmtproto "github.com/cometbft/cometbft/api/cometbft/types/v1"
	"github.com/cometbft/cometbft/crypto/tmhash"
	"github.com/cometbft/cometbft/libs/bytes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlobIDValidateBasic(t *testing.T) {
	validBlobID := BlobID{
		Hash: bytes.HexBytes{},
		PartSetHeader: PartSetHeader{
			Total: 1,
			Hash:  bytes.HexBytes{},
		},
	}

	invalidBlobID := BlobID{
		Hash: []byte{0},
		PartSetHeader: PartSetHeader{
			Total: 1,
			Hash:  []byte{0},
		},
	}

	testCases := []struct {
		name                string
		blobIDHash          bytes.HexBytes
		blobIDPartSetHeader PartSetHeader
		wantErr             bool
	}{
		{"ValidBlobID", validBlobID.Hash, validBlobID.PartSetHeader, false},
		{"InvalidBlobID", invalidBlobID.Hash, validBlobID.PartSetHeader, true},
		{"InvalidBlobID", validBlobID.Hash, invalidBlobID.PartSetHeader, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			blobID := BlobID{
				Hash:          tc.blobIDHash,
				PartSetHeader: tc.blobIDPartSetHeader,
			}

			gotErr := blobID.ValidateBasic()

			assert.Equal(t, tc.wantErr, gotErr != nil, "unexpected result")
		})
	}
}

func TestBlobIDIsComplete(t *testing.T) {
	var (
		reusableBuf = make([]byte, tmhash.Size)
		testCases   = []struct {
			name       string
			blobID     BlobID
			wantResult bool
		}{
			{
				name: "Complete",
				blobID: BlobID{
					Hash:          reusableBuf,
					PartSetHeader: PartSetHeader{Total: 2, Hash: reusableBuf},
				},
				wantResult: true,
			},
			{
				name:       "HashFalse",
				blobID:     BlobID{Hash: []byte("hash")},
				wantResult: false,
			},
			{
				name:       "PartSetSizeFalse",
				blobID:     BlobID{Hash: reusableBuf},
				wantResult: false,
			},
			{
				name: "PartSetHashFalse",
				blobID: BlobID{
					Hash:          reusableBuf,
					PartSetHeader: PartSetHeader{Total: 2},
				},
				wantResult: false,
			},
		}
	)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantResult, tc.blobID.IsComplete())
		})
	}
}

func TestBlobIDProtoBuf(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		var (
			bIDHash        = []byte("hash")
			bIDPartSetSize = uint32(2)
			bIDPartSetHash = []byte("part_set_hash")
			bID            = mockBlobID(bIDHash, bIDPartSetSize, bIDPartSetHash)

			testCases = []struct {
				name    string
				blobID  BlobID
				wantErr error
			}{
				{"FullBlob", bID, nil},
				{"EmptyBlob", BlobID{}, nil},
			}
		)

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				protoBlobID := tc.blobID.ToProto()

				blobID, err := BlobIDFromProto(&protoBlobID)
				require.NoError(t, err)
				require.Equal(t, tc.blobID, blobID)
			})
		}
	})

	t.Run("FailureInvalidBlobID", func(t *testing.T) {
		testCases := []struct {
			name        string
			protoBlobID *cmtproto.BlobID
			wantErrStr  string
		}{
			{
				name:        "NilPtr",
				protoBlobID: nil,
				wantErrStr:  "nil BlobID",
			},
			{
				name: "Hash",
				protoBlobID: &cmtproto.BlobID{
					Hash: []byte{0},
				},
				wantErrStr: "validating BlobID: wrong Hash",
			},
			{
				name: "PartSetHeader",
				protoBlobID: &cmtproto.BlobID{
					Hash: make([]byte, tmhash.Size),
					PartSetHeader: cmtproto.PartSetHeader{
						Total: 1,
						Hash:  []byte{0},
					},
				},
				wantErrStr: "wrong Hash: expected size to be 32 bytes, got 1 bytes",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				blobID, err := BlobIDFromProto(tc.protoBlobID)
				require.EqualError(t, err, tc.wantErrStr)
				require.Equal(t, BlobID{}, blobID)
			})
		}
	})
}

func mockBlobID(hash []byte, partSetSize uint32, partSetHash []byte) BlobID {
	var (
		h   = make([]byte, tmhash.Size)
		psh = make([]byte, tmhash.Size)
	)
	copy(h, hash)
	copy(psh, partSetHash)

	blobID := BlobID{
		Hash: h,
		PartSetHeader: PartSetHeader{
			Total: partSetSize,
			Hash:  psh,
		},
	}

	return blobID
}
