package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/bls12381"
)

func TestValidatorProtoBuf(t *testing.T) {
	val, _ := RandValidator(true, 100)

	// FIXME: we have to do this manual conversion because val's PubKey is set to
	// type bls12381.PubKey, but we expect it to be of type *bls12381.PubKey.
	// The long-term solution is to revisit the method bls12381.PubKey() to make it
	// return a *bls12381.PubKey.
	valPubKey := val.PubKey.(bls12381.PubKey)
	val.PubKey = &valPubKey

	testCases := []struct {
		msg      string
		v1       *Validator
		expPass1 bool
		expPass2 bool
	}{
		{"success validator", val, true, true},
		{"failure empty", &Validator{}, false, false},
		{"failure nil", nil, false, false},
	}
	for _, tc := range testCases {
		protoVal, err := tc.v1.ToProto()

		if tc.expPass1 {
			require.NoError(t, err, tc.msg)
		} else {
			require.Error(t, err, tc.msg)
		}

		val, err := ValidatorFromProto(protoVal)
		if tc.expPass2 {
			require.NoError(t, err, tc.msg)
			require.Equal(t, tc.v1, val, tc.msg)
		} else {
			require.Error(t, err, tc.msg)
		}
	}
}

type unsupportedPubKey struct{}

func (unsupportedPubKey) Address() crypto.Address             { return nil }
func (unsupportedPubKey) Bytes() []byte                       { return nil }
func (unsupportedPubKey) VerifySignature([]byte, []byte) bool { return false }
func (unsupportedPubKey) Type() string                        { return "unsupportedPubKey" }

func TestValidatorValidateBasic(t *testing.T) {
	priv := NewMockPV()
	pubKey, _ := priv.GetPubKey()
	testCases := []struct {
		val *Validator
		err bool
		msg string
	}{
		{
			val: NewValidator(pubKey, 1),
			err: false,
			msg: "",
		},
		{
			val: nil,
			err: true,
			msg: "nil validator",
		},
		{
			val: &Validator{
				PubKey: nil,
			},
			err: true,
			msg: "validator does not have a public key",
		},
		{
			val: NewValidator(pubKey, -1),
			err: true,
			msg: "validator has negative voting power",
		},
		{
			val: &Validator{
				PubKey:  pubKey,
				Address: nil,
			},
			err: true,
			msg: fmt.Sprintf("validator address is incorrectly derived from pubkey. Exp: %v, got ", pubKey.Address()),
		},
		{
			val: &Validator{
				PubKey:  pubKey,
				Address: []byte{'a'},
			},
			err: true,
			msg: fmt.Sprintf("validator address is incorrectly derived from pubkey. Exp: %v, got 61", pubKey.Address()),
		},
		{
			val: &Validator{
				PubKey:  unsupportedPubKey{},
				Address: unsupportedPubKey{}.Address(),
			},
			err: true,
			msg: ErrUnsupportedPubKeyType.Error(),
		},
	}

	for _, tc := range testCases {
		err := tc.val.ValidateBasic()
		if tc.err {
			if assert.Error(t, err) { //nolint:testifylint // require.Error doesn't work with the conditional here
				assert.Equal(t, tc.msg, err.Error())
			}
		} else {
			require.NoError(t, err)
		}
	}
}

// TestValidatorCopy tests if the Copy() method of a validator does
// a deep copy of all the fields.
func TestValidatorCopy(t *testing.T) {
	priv := NewMockPV()
	pubKey, _ := priv.GetPubKey()
	val := &Validator{
		Address:          pubKey.Address(),
		PubKey:           pubKey,
		VotingPower:      10,
		ProposerPriority: 1,
	}
	copyVal := val.Copy()
	assert.Equal(t, val.Address.Bytes(), copyVal.Address.Bytes())
	assert.Equal(t, val.PubKey.Bytes(), copyVal.PubKey.Bytes())
	assert.Equal(t, val.VotingPower, copyVal.VotingPower)
	assert.Equal(t, val.ProposerPriority, copyVal.ProposerPriority)
}
