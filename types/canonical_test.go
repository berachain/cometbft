package types

import (
	"reflect"
	"testing"

	cmtproto "github.com/cometbft/cometbft/api/cometbft/types/v1"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtrand "github.com/cometbft/cometbft/internal/rand"
	"github.com/stretchr/testify/require"
)

func TestCanonicalizeBlockID(t *testing.T) {
	randhash := cmtrand.Bytes(tmhash.Size)
	block1 := cmtproto.BlockID{
		Hash:          randhash,
		PartSetHeader: cmtproto.PartSetHeader{Total: 5, Hash: randhash},
	}
	block2 := cmtproto.BlockID{
		Hash:          randhash,
		PartSetHeader: cmtproto.PartSetHeader{Total: 10, Hash: randhash},
	}
	cblock1 := cmtproto.CanonicalBlockID{
		Hash:          randhash,
		PartSetHeader: cmtproto.CanonicalPartSetHeader{Total: 5, Hash: randhash},
	}
	cblock2 := cmtproto.CanonicalBlockID{
		Hash:          randhash,
		PartSetHeader: cmtproto.CanonicalPartSetHeader{Total: 10, Hash: randhash},
	}

	tests := []struct {
		name string
		args cmtproto.BlockID
		want *cmtproto.CanonicalBlockID
	}{
		{"first", block1, &cblock1},
		{"second", block2, &cblock2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CanonicalizeBlockID(tt.args); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CanonicalizeBlockID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCanonicalizeBlobID(t *testing.T) {
	var (
		randhash = cmtrand.Bytes(tmhash.Size)
		blob1    = cmtproto.BlobID{
			Hash:          randhash,
			PartSetHeader: cmtproto.PartSetHeader{Total: 5, Hash: randhash},
		}
		blob2 = cmtproto.BlobID{
			Hash:          randhash,
			PartSetHeader: cmtproto.PartSetHeader{Total: 10, Hash: randhash},
		}
		canonBlob1 = cmtproto.CanonicalBlobID{
			Hash:          randhash,
			PartSetHeader: cmtproto.CanonicalPartSetHeader{Total: 5, Hash: randhash},
		}
		canonBlob2 = cmtproto.CanonicalBlobID{
			Hash:          randhash,
			PartSetHeader: cmtproto.CanonicalPartSetHeader{Total: 10, Hash: randhash},
		}

		tests = []struct {
			name        string
			protoBlobID cmtproto.BlobID
			want        *cmtproto.CanonicalBlobID
		}{
			{"first", blob1, &canonBlob1},
			{"second", blob2, &canonBlob2},
		}
	)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CanonicalizeBlobID(tt.protoBlobID)
			require.Equal(t, tt.want, got)
		})
	}
}
