package encoding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/bls12381"
)

type unsupportedPubKey struct{}

func (unsupportedPubKey) Address() crypto.Address             { return nil }
func (unsupportedPubKey) Bytes() []byte                       { return nil }
func (unsupportedPubKey) VerifySignature([]byte, []byte) bool { return false }
func (unsupportedPubKey) Type() string                        { return "unsupportedPubKey" }

func TestPubKeyToFromProto(t *testing.T) {

	// bls12381
	privk, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	pk := privk.PubKey()
	proto, err := PubKeyToProto(pk)
	require.NoError(t, err)

	pubkey, err := PubKeyFromProto(proto)
	require.NoError(t, err)
	assert.Equal(t, pk, pubkey)

	// bls12381
	privk, err = bls12381.GenPrivKey()
	require.NoError(t, err)
	pk = privk.PubKey()
	proto, err = PubKeyToProto(pk)
	require.NoError(t, err)

	pubkey, err = PubKeyFromProto(proto)
	require.NoError(t, err)
	assert.Equal(t, pk, pubkey)

	// bls12381
	if bls12381.Enabled {
		privKey, err := bls12381.GenPrivKey()
		require.NoError(t, err)
		defer privKey.Zeroize()
		pk = privKey.PubKey()
		proto, err := PubKeyToProto(pk)
		require.NoError(t, err)

		pubkey, err := PubKeyFromProto(proto)
		require.NoError(t, err)
		assert.Equal(t, pk, pubkey)
	} else {
		_, err = PubKeyToProto(bls12381.PubKey{})
		assert.Error(t, err)
	}

	// unsupported key type
	_, err = PubKeyToProto(unsupportedPubKey{})
	require.Error(t, err)
	assert.Equal(t, ErrUnsupportedKey{KeyType: unsupportedPubKey{}.Type()}, err)
}

func TestPubKeyFromTypeAndBytes(t *testing.T) {
	// bls12381
	privk, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	pk := privk.PubKey()
	pubkey, err := PubKeyFromTypeAndBytes(pk.Type(), pk.Bytes())
	assert.NoError(t, err)
	assert.Equal(t, pk, pubkey)

	// bls12381 invalid size
	_, err = PubKeyFromTypeAndBytes(pk.Type(), pk.Bytes()[:10])
	assert.Error(t, err)

	// bls12381
	privk, err = bls12381.GenPrivKey()
	require.NoError(t, err)
	pk = privk.PubKey()
	pubkey, err = PubKeyFromTypeAndBytes(pk.Type(), pk.Bytes())
	assert.NoError(t, err)
	assert.Equal(t, pk, pubkey)

	// bls12381 invalid size
	_, err = PubKeyFromTypeAndBytes(pk.Type(), pk.Bytes()[:10])
	assert.Error(t, err)

	// bls12381
	if bls12381.Enabled {
		privKey, err := bls12381.GenPrivKey()
		require.NoError(t, err)
		pk := privKey.PubKey()
		pubkey, err = PubKeyFromTypeAndBytes(pk.Type(), pk.Bytes())
		assert.NoError(t, err)
		assert.Equal(t, pk, pubkey)

		// bls12381 invalid size
		_, err = PubKeyFromTypeAndBytes(pk.Type(), pk.Bytes()[:10])
		assert.Error(t, err)
	} else {
		panic("bls has to be enabled")
	}
}
