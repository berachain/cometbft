package types

import (
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto"
	cryptoenc "github.com/cometbft/cometbft/crypto/encoding"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

//-------------------------------------------------------

// TM2PB is used for converting CometBFT ABCI to protobuf ABCI.
// UNSTABLE
var TM2PB = tm2pb{}

type tm2pb struct{}

func (tm2pb) Header(header *Header) cmtproto.Header {
	return cmtproto.Header{
		Version: header.Version,
		ChainID: header.ChainID,
		Height:  header.Height,
		Time:    header.Time,

		LastBlockId: header.LastBlockID.ToProto(),

		LastCommitHash: header.LastCommitHash,
		DataHash:       header.DataHash,

		ValidatorsHash:     header.ValidatorsHash,
		NextValidatorsHash: header.NextValidatorsHash,
		ConsensusHash:      header.ConsensusHash,
		AppHash:            header.AppHash,
		LastResultsHash:    header.LastResultsHash,

		EvidenceHash:    header.EvidenceHash,
		ProposerAddress: header.ProposerAddress,
	}
}

func (tm2pb) Validator(val *Validator) abci.Validator {
	return abci.Validator{
		Address: val.PubKey.Address(),
		Power:   val.VotingPower,
	}
}

func (tm2pb) BlockID(blockID BlockID) cmtproto.BlockID {
	return cmtproto.BlockID{
		Hash:          blockID.Hash,
		PartSetHeader: TM2PB.PartSetHeader(blockID.PartSetHeader),
	}
}

func (tm2pb) PartSetHeader(header PartSetHeader) cmtproto.PartSetHeader {
	return cmtproto.PartSetHeader{
		Total: header.Total,
		Hash:  header.Hash,
	}
}

// XXX: panics on unknown pubkey type
func (tm2pb) ValidatorUpdate(val *Validator) abci.ValidatorUpdate {
	pk, err := cryptoenc.PubKeyToProto(val.PubKey)
	if err != nil {
		panic(err)
	}
	return abci.ValidatorUpdate{
		PubKey: pk,
		Power:  val.VotingPower,
	}
}

// XXX: panics on nil or unknown pubkey type
func (tm2pb) ValidatorUpdates(vals *ValidatorSet) []abci.ValidatorUpdate {
	validators := make([]abci.ValidatorUpdate, vals.Size())
	for i, val := range vals.Validators {
		validators[i] = TM2PB.ValidatorUpdate(val)
	}
	return validators
}

// XXX: panics on nil or unknown pubkey type
func (tm2pb) NewValidatorUpdate(pubkey crypto.PubKey, power int64) abci.ValidatorUpdate {
	pubkeyABCI, err := cryptoenc.PubKeyToProto(pubkey)
	if err != nil {
		panic(err)
	}
	return abci.ValidatorUpdate{
		PubKey: pubkeyABCI,
		Power:  power,
	}
}

//----------------------------------------------------------------------------

// PB2TM is used for converting protobuf ABCI to CometBFT ABCI.
// UNSTABLE
var PB2TM = pb2tm{}

type pb2tm struct{}

func (pb2tm) ValidatorUpdates(vals []abci.ValidatorUpdate) ([]*Validator, error) {
	cmtVals := make([]*Validator, len(vals))
	for i, v := range vals {
		pub, err := PubKeyFromValidatorUpdate(v)
		if err != nil {
			return nil, err
		}
		cmtVals[i] = NewValidator(pub, v.Power)
	}
	return cmtVals, nil
}

// PubKeyFromValidatorUpdate extracts the public key from an ABCI validator
// update. It accepts both encodings: the proto PublicKey in pub_key (upstream
// and this fork) and the raw pub_key_bytes + pub_key_type pair written by the
// bera-v1.x line. pub_key takes precedence when both are set.
func PubKeyFromValidatorUpdate(v abci.ValidatorUpdate) (crypto.PubKey, error) {
	if v.PubKey.Sum == nil && v.PubKeyType != "" {
		return cryptoenc.PubKeyFromTypeAndBytes(v.PubKeyType, v.PubKeyBytes)
	}
	return cryptoenc.PubKeyFromProto(v.PubKey)
}

// NormalizeValidatorUpdates returns a copy of the validator updates in which
// every entry carries both public key encodings (pub_key, and
// pub_key_bytes + pub_key_type) so that the persisted form can be read by both
// this fork and the bera-v1.x line. Entries whose key cannot be decoded are
// left untouched.
func NormalizeValidatorUpdates(vals []abci.ValidatorUpdate) []abci.ValidatorUpdate {
	if len(vals) == 0 {
		return vals
	}
	out := make([]abci.ValidatorUpdate, len(vals))
	copy(out, vals)
	for i := range out {
		pub, err := PubKeyFromValidatorUpdate(out[i])
		if err != nil {
			continue
		}
		if out[i].PubKey.Sum == nil {
			if pk, err := cryptoenc.PubKeyToProto(pub); err == nil {
				out[i].PubKey = pk
			}
		}
		if out[i].PubKeyType == "" {
			out[i].PubKeyType = pub.Type()
			out[i].PubKeyBytes = pub.Bytes()
		}
	}
	return out
}
