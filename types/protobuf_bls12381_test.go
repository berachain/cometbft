//go:build bls12381

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/bls12381"
	cryptoenc "github.com/cometbft/cometbft/crypto/encoding"
)

// A raw-only (bera-v1.x) validator update keeps its raw key bytes as given,
// here a compressed BLS key, and gains the equivalent proto pub_key.
func TestNormalizeValidatorUpdatesKeepsCompressedBLSKey(t *testing.T) {
	priv, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	pubkey := priv.PubKey()
	compressed := pubkey.(interface{ Compress() []byte }).Compress()
	require.Len(t, compressed, bls12381.PubKeyCompressedSize)

	in := []abci.ValidatorUpdate{{PubKeyBytes: compressed, PubKeyType: bls12381.KeyType, Power: 1}}
	out := NormalizeValidatorUpdates(in)
	require.Len(t, out, 1)
	assert.Equal(t, compressed, out[0].PubKeyBytes)
	assert.Equal(t, bls12381.KeyType, out[0].PubKeyType)

	fromProto, err := cryptoenc.PubKeyFromProto(out[0].PubKey)
	require.NoError(t, err)
	assert.True(t, pubkey.Equals(fromProto))
}
