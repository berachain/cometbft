package types

import (
	"fmt"
	"testing"

	ce "github.com/cometbft/cometbft/crypto/encoding"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidatorProtoBuf(t *testing.T) {
	val, _ := RandValidator(true, 100)
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

func TestValidatorBytesCommitPubKeyAndVotingPower(t *testing.T) {
	val, _ := RandValidator(true, 100)
	pk, err := ce.PubKeyToProto(val.PubKey)
	require.NoError(t, err)
	want := cmtproto.SimpleValidator{
		PubKey:      &pk,
		VotingPower: val.VotingPower,
	}
	wantBz, err := want.Marshal()
	require.NoError(t, err)

	require.Equal(t, wantBz, val.Bytes())
}

// Malformed validators from a peer return an error instead of panicking.
func TestValidatorFromProtoNoPanicOnNilPubKey(t *testing.T) {
	for _, vp := range []*cmtproto.Validator{
		{},                      // no key at all
		{PubKeyType: "unknown"}, // unknown key type
		{PubKeyType: "bls12_381", PubKeyBytes: []byte{1, 2}}, // truncated key
	} {
		require.NotPanics(t, func() {
			v, err := ValidatorFromProto(vp)
			require.Error(t, err)
			require.Nil(t, v)
		})
	}
}

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
	}

	for _, tc := range testCases {
		err := tc.val.ValidateBasic()
		if tc.err {
			if assert.Error(t, err) {
				assert.Equal(t, tc.msg, err.Error())
			}
		} else {
			assert.NoError(t, err)
		}
	}
}
