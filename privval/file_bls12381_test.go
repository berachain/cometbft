//go:build bls12381

package privval

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/bls12381"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/secp256k1"
)

// SignBytes signs raw bytes with the validator key. beacon-kit's BLSSigner
// relies on it for BLS keys.
func TestSignBytes(t *testing.T) {
	blsKey, err := bls12381.GenPrivKey()
	require.NoError(t, err)
	for _, pk := range []crypto.PrivKey{ed25519.GenPrivKey(), secp256k1.GenPrivKey(), blsKey} {
		t.Run(pk.Type(), func(t *testing.T) {
			dir := t.TempDir()
			pv := NewFilePV(pk, filepath.Join(dir, "key.json"), filepath.Join(dir, "state.json"))
			msg := []byte("bytes to sign")
			sig, err := pv.SignBytes(msg)
			require.NoError(t, err)
			require.True(t, pk.PubKey().VerifySignature(msg, sig))
		})
	}
}
