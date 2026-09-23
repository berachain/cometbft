package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cryptoenc "github.com/cometbft/cometbft/crypto/encoding"
)

func TestABCIPubKey(t *testing.T) {
	pkEd := ed25519.GenPrivKey().PubKey()
	err := testABCIPubKey(t, pkEd)
	assert.NoError(t, err)
}

func testABCIPubKey(t *testing.T, pk crypto.PubKey) error {
	abciPubKey, err := cryptoenc.PubKeyToProto(pk)
	require.NoError(t, err)
	pk2, err := cryptoenc.PubKeyFromProto(abciPubKey)
	require.NoError(t, err)
	require.Equal(t, pk, pk2)
	return nil
}

func TestABCIValidators(t *testing.T) {
	pkEd := ed25519.GenPrivKey().PubKey()

	// correct validator
	cmtValExpected := NewValidator(pkEd, 10)

	cmtVal := NewValidator(pkEd, 10)

	abciVal := TM2PB.ValidatorUpdate(cmtVal)
	cmtVals, err := PB2TM.ValidatorUpdates([]abci.ValidatorUpdate{abciVal})
	assert.Nil(t, err)
	assert.Equal(t, cmtValExpected, cmtVals[0])

	abciVals := TM2PB.ValidatorUpdates(NewValidatorSet(cmtVals))
	assert.Equal(t, []abci.ValidatorUpdate{abciVal}, abciVals)

	// val with address
	cmtVal.Address = pkEd.Address()

	abciVal = TM2PB.ValidatorUpdate(cmtVal)
	cmtVals, err = PB2TM.ValidatorUpdates([]abci.ValidatorUpdate{abciVal})
	assert.Nil(t, err)
	assert.Equal(t, cmtValExpected, cmtVals[0])
}

type pubKeyEddie struct{}

func (pubKeyEddie) Address() Address                    { return []byte{} }
func (pubKeyEddie) Bytes() []byte                       { return []byte{} }
func (pubKeyEddie) VerifySignature([]byte, []byte) bool { return false }
func (pubKeyEddie) Equals(crypto.PubKey) bool           { return false }
func (pubKeyEddie) String() string                      { return "" }
func (pubKeyEddie) Type() string                        { return "pubKeyEddie" }

func TestABCIValidatorFromPubKeyAndPower(t *testing.T) {
	pubkey := ed25519.GenPrivKey().PubKey()

	abciVal := TM2PB.NewValidatorUpdate(pubkey, 10)
	assert.Equal(t, int64(10), abciVal.Power)

	assert.Panics(t, func() { TM2PB.NewValidatorUpdate(nil, 10) })
	assert.Panics(t, func() { TM2PB.NewValidatorUpdate(pubKeyEddie{}, 10) })
}

func TestABCIValidatorWithoutPubKey(t *testing.T) {
	pkEd := ed25519.GenPrivKey().PubKey()

	abciVal := TM2PB.Validator(NewValidator(pkEd, 10))

	// pubkey must be nil
	cmtValExpected := abci.Validator{
		Address: pkEd.Address(),
		Power:   10,
	}

	assert.Equal(t, cmtValExpected, abciVal)
}

// The bera-v1.x line encodes ValidatorUpdate public keys as pub_key_bytes +
// pub_key_type; this fork (like upstream) uses the proto PublicKey in pub_key.
// Both must be readable, and persisted updates carry both.
func TestABCIValidatorUpdatesAcceptBothPubKeyEncodings(t *testing.T) {
	pubkey := ed25519.GenPrivKey().PubKey()
	pkProto, err := cryptoenc.PubKeyToProto(pubkey)
	require.NoError(t, err)

	// upstream / bera-v0.40.x encoding
	vals, err := PB2TM.ValidatorUpdates([]abci.ValidatorUpdate{{PubKey: pkProto, Power: 10}})
	require.NoError(t, err)
	require.Len(t, vals, 1)
	assert.True(t, pubkey.Equals(vals[0].PubKey))

	// bera-v1.x encoding
	vals, err = PB2TM.ValidatorUpdates([]abci.ValidatorUpdate{{
		PubKeyBytes: pubkey.Bytes(),
		PubKeyType:  pubkey.Type(),
		Power:       10,
	}})
	require.NoError(t, err)
	require.Len(t, vals, 1)
	assert.True(t, pubkey.Equals(vals[0].PubKey))

	// pub_key wins when both are present and disagree
	other := ed25519.GenPrivKey().PubKey()
	vals, err = PB2TM.ValidatorUpdates([]abci.ValidatorUpdate{{
		PubKey:      pkProto,
		PubKeyBytes: other.Bytes(),
		PubKeyType:  other.Type(),
		Power:       10,
	}})
	require.NoError(t, err)
	assert.True(t, pubkey.Equals(vals[0].PubKey))

	// neither present is still an error
	_, err = PB2TM.ValidatorUpdates([]abci.ValidatorUpdate{{Power: 10}})
	require.Error(t, err)
}

func TestNormalizeValidatorUpdates(t *testing.T) {
	pubkey := ed25519.GenPrivKey().PubKey()
	pkProto, err := cryptoenc.PubKeyToProto(pubkey)
	require.NoError(t, err)

	other := ed25519.GenPrivKey().PubKey()

	in := []abci.ValidatorUpdate{
		{PubKey: pkProto, Power: 1},
		{PubKeyBytes: pubkey.Bytes(), PubKeyType: pubkey.Type(), Power: 2},
		// pub_key and raw fields disagree: pub_key is the key that is
		// applied, so the raw fields are rewritten from it
		{PubKey: pkProto, PubKeyBytes: other.Bytes(), PubKeyType: other.Type(), Power: 4},
		{Power: 3}, // undecodable, left untouched
	}
	out := NormalizeValidatorUpdates(in)
	require.Len(t, out, 4)
	for _, v := range out[:3] {
		assert.Equal(t, pkProto, v.PubKey)
		assert.Equal(t, pubkey.Bytes(), v.PubKeyBytes)
		assert.Equal(t, pubkey.Type(), v.PubKeyType)
		// both encodings decode to the same key
		raw, err := cryptoenc.PubKeyFromTypeAndBytes(v.PubKeyType, v.PubKeyBytes)
		require.NoError(t, err)
		assert.True(t, pubkey.Equals(raw))
	}
	assert.Equal(t, in[3], out[3])
	assert.Equal(t, other.Bytes(), in[2].PubKeyBytes)
	// input is not mutated
	assert.Nil(t, in[0].PubKeyBytes)
	assert.Nil(t, in[1].PubKey.Sum)
	assert.Nil(t, NormalizeValidatorUpdates(nil))
}
