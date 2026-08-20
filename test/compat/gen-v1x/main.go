// Command gen-v1x produces the bera-v1.x golden vectors consumed by
// test/compat/vectors_test.go.
//
// It must be built against the bera-v1.x line (see go.mod in this directory),
// and it writes a JSON document to stdout. Every value is derived from fixed
// inputs (the same inputs are hard-coded in vectors_test.go), so the output is
// fully deterministic and can be regenerated at any time:
//
//	cd test/compat/gen-v1x && go run . > ../vectors/bera_v1x_vectors.json
//
// NOTE: this program deliberately uses only public bera-v1.x packages (types,
// privval, state, crypto, api protos). Consensus and WAL wire messages are
// built directly from their proto types.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	gogo "github.com/cosmos/gogoproto/types"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtcons "github.com/cometbft/cometbft/api/cometbft/consensus/v1"
	cmtbits "github.com/cometbft/cometbft/api/cometbft/libs/bits/v1"
	cmtstate "github.com/cometbft/cometbft/api/cometbft/state/v1"
	cmtstore "github.com/cometbft/cometbft/api/cometbft/store/v1"
	cmtproto "github.com/cometbft/cometbft/api/cometbft/types/v1"
	cmtversion "github.com/cometbft/cometbft/api/cometbft/version/v1"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/bls12381"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/types"
)

// Fixed inputs. Keep in sync with vectors_test.go.
const (
	chainID  = "bera-compat-1"
	height   = int64(1234)
	round    = int32(2)
	numVals  = 4
	blsSeed  = "bera-compat-bls-val-"
	ed25Seed = "bera-compat-ed25519-val"
)

var (
	fixedTime     = time.Date(2026, 1, 2, 3, 4, 5, 600000000, time.UTC)
	fixedTimeNext = fixedTime.Add(2 * time.Second)
	powers        = []int64{10, 20, 30, 40}
)

func h32(label string) []byte { s := sha256.Sum256([]byte(label)); return s[:] }

func must(err error) {
	if err != nil {
		panic(err)
	}
}

type out map[string]any

func hx(b []byte) string { return hex.EncodeToString(b) }

func main() {
	verifyPath := flag.String("verify", "", "path to bera-v0.40.x outputs (written by TestWriteV040Outputs); when set, compare and decode them with bera-v1.x code instead of printing vectors")
	flag.Parse()

	v := generate()
	if *verifyPath != "" {
		os.Exit(verify(v, *verifyPath))
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(enc.Encode(v))
}

func generate() out {
	v := out{}

	// ---- keys & validators -------------------------------------------------
	blsPrivs := make([]*bls12381.PrivKey, numVals)
	blsVals := make([]*types.Validator, numVals)
	for i := 0; i < numVals; i++ {
		pk, err := bls12381.GenPrivKeyFromSecret([]byte(fmt.Sprintf("%s%d", blsSeed, i)))
		must(err)
		blsPrivs[i] = pk
		blsVals[i] = types.NewValidator(pk.PubKey(), powers[i])
		v[fmt.Sprintf("bls_pubkey_%d", i)] = hx(pk.PubKey().Bytes())
		v[fmt.Sprintf("bls_pubkey_compressed_%d", i)] = hx(compress(pk.PubKey()))
		v[fmt.Sprintf("bls_address_%d", i)] = hx(pk.PubKey().Address())
	}
	blsValSet := types.NewValidatorSet(blsVals)
	// NewValidatorSet sorts validators (by power, then address); keep the
	// private keys aligned with the set's order so that validator index i
	// always refers to blsValSet.Validators[i].
	blsVals, blsPrivs = sortKeys(blsValSet, blsVals, blsPrivs)
	v["bls_valset_hash"] = hx(blsValSet.Hash())
	vsp, err := blsValSet.ToProto()
	must(err)
	bz, err := vsp.Marshal()
	must(err)
	v["bls_valset_proto"] = hx(bz)
	vp, err := blsVals[0].ToProto()
	must(err)
	bz, err = vp.Marshal()
	must(err)
	v["bls_validator0_proto"] = hx(bz)
	v["bls_validator0_bytes"] = hx(blsVals[0].Bytes()) // SimpleValidator encoding used by ValidatorSet.Hash

	edPriv := ed25519.GenPrivKeyFromSecret([]byte(ed25Seed))
	edVal := types.NewValidator(edPriv.PubKey(), 5)
	v["ed25519_pubkey"] = hx(edPriv.PubKey().Bytes())
	v["ed25519_address"] = hx(edPriv.PubKey().Address())
	vp, err = edVal.ToProto()
	must(err)
	bz, err = vp.Marshal()
	must(err)
	v["ed25519_validator_proto"] = hx(bz)
	edVals := make([]*types.Validator, numVals)
	edPrivs := make([]ed25519.PrivKey, numVals)
	for i := 0; i < numVals; i++ {
		edPrivs[i] = ed25519.GenPrivKeyFromSecret([]byte(fmt.Sprintf("%s-%d", ed25Seed, i)))
		edVals[i] = types.NewValidator(edPrivs[i].PubKey(), powers[i])
	}
	edValSet := types.NewValidatorSet(edVals)
	edVals, edPrivs = sortKeys(edValSet, edVals, edPrivs)
	v["ed25519_valset_hash"] = hx(edValSet.Hash())

	// ---- block id, votes, proposal -------------------------------------------
	blockID := types.BlockID{
		Hash:          h32("block"),
		PartSetHeader: types.PartSetHeader{Total: 3, Hash: h32("parts")},
	}
	bidp := blockID.ToProto()
	bz, err = bidp.Marshal()
	must(err)
	v["blockid_proto"] = hx(bz)

	mkVote := func(t types.SignedMsgType, bid types.BlockID, valIdx int32, addr []byte) *types.Vote {
		return &types.Vote{
			Type:             t,
			Height:           height,
			Round:            round,
			BlockID:          bid,
			ValidatorAddress: addr,
			ValidatorIndex:   valIdx,
			Timestamp:        time.Time{}, // per-vote timestamps are not used on this fork
		}
	}
	precommit := mkVote(types.PrecommitType, blockID, 0, blsVals[0].Address)
	prevote := mkVote(types.PrevoteType, blockID, 0, blsVals[0].Address)
	nilPrecommit := mkVote(types.PrecommitType, types.BlockID{}, 3, blsVals[3].Address)
	v["vote_sign_bytes_precommit"] = hx(types.VoteSignBytes(chainID, precommit.ToProto()))
	v["vote_sign_bytes_prevote"] = hx(types.VoteSignBytes(chainID, prevote.ToProto()))
	v["vote_sign_bytes_nil_precommit"] = hx(types.VoteSignBytes(chainID, nilPrecommit.ToProto()))
	sig, err := blsPrivs[0].Sign(types.VoteSignBytes(chainID, precommit.ToProto()))
	must(err)
	v["vote_bls_signature_val0_precommit"] = hx(sig)
	precommit.Signature = sig
	bz, err = precommit.ToProto().Marshal()
	must(err)
	v["vote_proto_signed_precommit"] = hx(bz)
	// a vote carrying a non-zero timestamp must still sign identically (timestamp is not signed)
	tsVote := mkVote(types.PrecommitType, blockID, 0, blsVals[0].Address)
	tsVote.Timestamp = fixedTime
	v["vote_sign_bytes_precommit_with_timestamp"] = hx(types.VoteSignBytes(chainID, tsVote.ToProto()))

	proposal := types.NewProposal(height, round, 1, blockID, fixedTime)
	v["proposal_sign_bytes"] = hx(types.ProposalSignBytes(chainID, proposal.ToProto()))
	psig, err := blsPrivs[1].Sign(types.ProposalSignBytes(chainID, proposal.ToProto()))
	must(err)
	v["proposal_bls_signature_val1"] = hx(psig)
	proposal.Signature = psig
	bz, err = proposal.ToProto().Marshal()
	must(err)
	v["proposal_proto_signed"] = hx(bz)

	// ---- aggregated commit (all-BLS set; vals 0..2 commit, val 3 nil) ---------
	voteSet := types.NewVoteSet(chainID, height, round, types.PrecommitType, blsValSet)
	for i := 0; i < numVals; i++ {
		bid := blockID
		if i == 3 {
			bid = types.BlockID{}
		}
		vote := mkVote(types.PrecommitType, bid, int32(i), blsVals[i].Address)
		vote.Signature, err = blsPrivs[i].Sign(types.VoteSignBytes(chainID, vote.ToProto()))
		must(err)
		added, err := voteSet.AddVote(vote)
		must(err)
		if !added {
			panic("vote not added")
		}
	}
	aggCommit := voteSet.MakeBLSCommit().ToCommit()
	bz, err = aggCommit.ToProto().Marshal()
	must(err)
	v["agg_commit_proto"] = hx(bz)
	v["agg_commit_hash"] = hx(aggCommit.Hash())
	for i, cs := range aggCommit.Signatures {
		v[fmt.Sprintf("agg_commit_sig%d_flag", i)] = int(cs.BlockIDFlag)
	}
	must(blsValSet.VerifyCommit(chainID, blockID, height, aggCommit))

	// all-commit variant (no nil votes)
	voteSet2 := types.NewVoteSet(chainID, height, round, types.PrecommitType, blsValSet)
	for i := 0; i < numVals; i++ {
		vote := mkVote(types.PrecommitType, blockID, int32(i), blsVals[i].Address)
		vote.Signature, err = blsPrivs[i].Sign(types.VoteSignBytes(chainID, vote.ToProto()))
		must(err)
		_, err = voteSet2.AddVote(vote)
		must(err)
	}
	aggCommitAll := voteSet2.MakeBLSCommit().ToCommit()
	bz, err = aggCommitAll.ToProto().Marshal()
	must(err)
	v["agg_commit_all_proto"] = hx(bz)
	v["agg_commit_all_hash"] = hx(aggCommitAll.Hash())

	// ---- individual-signature commit (ed25519 set) ------------------------------
	edVoteSet := types.NewVoteSet(chainID, height, round, types.PrecommitType, edValSet)
	for i := 0; i < numVals; i++ {
		bid := blockID
		if i == 1 {
			bid = types.BlockID{}
		}
		vote := mkVote(types.PrecommitType, bid, int32(i), edVals[i].Address)
		vote.Signature, err = edPrivs[i].Sign(types.VoteSignBytes(chainID, vote.ToProto()))
		must(err)
		_, err = edVoteSet.AddVote(vote)
		must(err)
	}
	edCommit := edVoteSet.MakeExtendedCommit(types.FeatureParams{}).ToCommit()
	bz, err = edCommit.ToProto().Marshal()
	must(err)
	v["ed25519_commit_proto"] = hx(bz)
	v["ed25519_commit_hash"] = hx(edCommit.Hash())

	// ---- consensus params ------------------------------------------------------
	params := consensusParams()
	v["params_hash"] = hx(params.Hash())
	pp := params.ToProto()
	bz, err = pp.Marshal()
	must(err)
	v["params_proto"] = hx(bz)
	bz, err = cmtjson.Marshal(params)
	must(err)
	v["params_json"] = string(bz)
	// a consensus-param update as returned by the app (FinalizeBlock)
	upd := &cmtproto.ConsensusParams{
		Block: &cmtproto.BlockParams{MaxBytes: 1, MaxGas: 2},
		Feature: &cmtproto.FeatureParams{
			SbtEnableHeight: &gogo.Int64Value{Value: 9},
		},
		Synchrony: &cmtproto.SynchronyParams{Precision: durPtr(1 * time.Second), MessageDelay: durPtr(3 * time.Second)},
	}
	bz, err = upd.Marshal()
	must(err)
	v["params_update_proto"] = hx(bz)
	updated := params.Update(upd)
	v["params_updated_hash"] = hx(updated.Hash())
	pp = updated.ToProto()
	bz, err = pp.Marshal()
	must(err)
	v["params_updated_proto"] = hx(bz)

	// ---- header / block --------------------------------------------------------
	lastBlockID := types.BlockID{Hash: h32("last-block"), PartSetHeader: types.PartSetHeader{Total: 1, Hash: h32("last-parts")}}
	txs := []types.Tx{types.Tx("tx-one"), types.Tx("tx-two")}
	block := types.MakeBlock(height+1, txs, aggCommit, nil)
	block.Header.Version = cmtversion.Consensus{Block: 11, App: 1}
	block.Header.ChainID = chainID
	block.Header.Time = fixedTimeNext
	block.Header.LastBlockID = lastBlockID
	block.Header.ValidatorsHash = blsValSet.Hash()
	block.Header.NextValidatorsHash = blsValSet.Hash()
	block.Header.ConsensusHash = params.Hash()
	block.Header.AppHash = h32("app")
	block.Header.LastResultsHash = h32("results")
	block.Header.ProposerAddress = blsVals[1].Address
	// evidence hash / data hash / last commit hash are derived
	block.Header.EvidenceHash = block.Evidence.Hash()
	block.Header.DataHash = block.Data.Hash()
	block.Header.LastCommitHash = aggCommit.Hash()
	v["header_hash"] = hx(block.Header.Hash())
	hp := block.Header.ToProto()
	bz, err = hp.Marshal()
	must(err)
	v["header_proto"] = hx(bz)
	v["block_hash"] = hx(block.Hash())
	bp, err := block.ToProto()
	must(err)
	bz, err = bp.Marshal()
	must(err)
	v["block_proto"] = hx(bz)
	ps, err := block.MakePartSet(types.BlockPartSizeBytes)
	must(err)
	v["block_partset_total"] = int(ps.Total())
	v["block_partset_hash"] = hx(ps.Hash())
	part := ps.GetPart(0)
	partp, err := part.ToProto()
	must(err)
	bz, err = partp.Marshal()
	must(err)
	v["block_part0_proto"] = hx(bz)
	v["data_hash"] = hx(block.Data.Hash())
	v["evidence_hash_empty"] = hx(block.Evidence.Hash())
	meta := types.NewBlockMeta(block, ps)
	bz, err = meta.ToProto().Marshal()
	must(err)
	v["block_meta_proto"] = hx(bz)

	// ---- evidence --------------------------------------------------------------
	voteA := mkVote(types.PrecommitType, blockID, 2, blsVals[2].Address)
	voteA.Signature, err = blsPrivs[2].Sign(types.VoteSignBytes(chainID, voteA.ToProto()))
	must(err)
	otherBlockID := types.BlockID{Hash: h32("other-block"), PartSetHeader: types.PartSetHeader{Total: 3, Hash: h32("other-parts")}}
	voteB := mkVote(types.PrecommitType, otherBlockID, 2, blsVals[2].Address)
	voteB.Signature, err = blsPrivs[2].Sign(types.VoteSignBytes(chainID, voteB.ToProto()))
	must(err)
	dve, err := types.NewDuplicateVoteEvidence(voteA, voteB, fixedTime, blsValSet)
	must(err)
	must(dve.ValidateBasic())
	v["dve_hash"] = hx(dve.Hash())
	evp, err := types.EvidenceToProto(dve)
	must(err)
	bz, err = evp.Marshal()
	must(err)
	v["dve_proto"] = hx(bz)
	v["dve_bytes"] = hx(dve.Bytes())
	evList := types.EvidenceList{dve}
	v["evidence_list_hash"] = hx(evList.Hash())

	// ---- persisted state -------------------------------------------------------
	state := sm.State{
		Version: cmtstate.Version{
			Consensus: cmtversion.Consensus{Block: 11, App: 1},
			Software:  "1.0.1",
		},
		ChainID:                          chainID,
		InitialHeight:                    1,
		LastBlockHeight:                  height,
		LastBlockID:                      blockID,
		LastBlockTime:                    fixedTime,
		NextValidators:                   blsValSet.Copy(),
		Validators:                       blsValSet.Copy(),
		LastValidators:                   blsValSet.Copy(),
		LastHeightValidatorsChanged:      100,
		ConsensusParams:                  params,
		LastHeightConsensusParamsChanged: 50,
		LastResultsHash:                  h32("results"),
		AppHash:                          h32("app"),
		NextBlockDelay:                   1500 * time.Millisecond,
	}
	sp, err := state.ToProto()
	must(err)
	bz, err = sp.Marshal()
	must(err)
	v["state_proto"] = hx(bz)
	valInfo := &cmtstate.ValidatorsInfo{ValidatorSet: vsp, LastHeightChanged: 100}
	bz, err = valInfo.Marshal()
	must(err)
	v["validators_info_proto"] = hx(bz)
	ppp := params.ToProto()
	cpInfo := &cmtstate.ConsensusParamsInfo{ConsensusParams: ppp, LastHeightChanged: 50}
	bz, err = cpInfo.Marshal()
	must(err)
	v["consensus_params_info_proto"] = hx(bz)

	// ---- ABCI responses as persisted by bera-v1.x ------------------------------
	fbr := &abci.FinalizeBlockResponse{
		Events:    []abci.Event{{Type: "t", Attributes: []abci.EventAttribute{{Key: "k", Value: "v", Index: true}}}},
		TxResults: []*abci.ExecTxResult{{Code: 0, Data: []byte("d"), GasWanted: 1, GasUsed: 1}},
		ValidatorUpdates: []abci.ValidatorUpdate{{
			PubKeyBytes: compress(blsPrivs[0].PubKey()),
			PubKeyType:  bls12381.KeyType,
			Power:       77,
		}},
		ConsensusParamUpdates: upd,
		AppHash:               h32("app-next"),
		NextBlockDelay:        1500 * time.Millisecond,
	}
	bz, err = fbr.Marshal()
	must(err)
	v["finalize_block_response_proto"] = hx(bz)
	respInfo := &cmtstate.ABCIResponsesInfo{FinalizeBlock: fbr, Height: height}
	bz, err = respInfo.Marshal()
	must(err)
	v["abci_responses_info_proto"] = hx(bz)
	v["abci_responses_info_legacy_field_check"] = "finalize_block=3"
	ppr := &abci.ProcessProposalRequest{
		Hash:                h32("block"),
		Height:              height,
		Time:                fixedTime,
		ProposerAddress:     blsVals[1].Address,
		NextValidatorsHash:  blsValSet.Hash(),
		NextProposerAddress: blsVals[2].Address,
	}
	bz, err = ppr.Marshal()
	must(err)
	v["process_proposal_request_proto"] = hx(bz)

	// ---- block store -----------------------------------------------------------
	bss := &cmtstore.BlockStoreState{Base: 1, Height: height}
	bz, err = bss.Marshal()
	must(err)
	v["block_store_state_proto"] = hx(bz)

	// ---- consensus p2p messages (wire) -----------------------------------------
	msgs := map[string]*cmtcons.Message{
		"p2p_new_round_step": {Sum: &cmtcons.Message_NewRoundStep{NewRoundStep: &cmtcons.NewRoundStep{
			Height: height, Round: round, Step: 3, SecondsSinceStartTime: 7, LastCommitRound: 1,
		}}},
		"p2p_new_valid_block": {Sum: &cmtcons.Message_NewValidBlock{NewValidBlock: &cmtcons.NewValidBlock{
			Height: height, Round: round, BlockPartSetHeader: blockID.PartSetHeader.ToProto(),
			BlockParts: bitArrayProto(3, 1), IsCommit: true,
		}}},
		"p2p_proposal":     {Sum: &cmtcons.Message_Proposal{Proposal: &cmtcons.Proposal{Proposal: *proposal.ToProto()}}},
		"p2p_proposal_pol": {Sum: &cmtcons.Message_ProposalPol{ProposalPol: &cmtcons.ProposalPOL{Height: height, ProposalPolRound: 1, ProposalPol: *bitArrayProto(4, 2)}}},
		"p2p_block_part":   {Sum: &cmtcons.Message_BlockPart{BlockPart: &cmtcons.BlockPart{Height: height + 1, Round: round, Part: *partp}}},
		"p2p_vote":         {Sum: &cmtcons.Message_Vote{Vote: &cmtcons.Vote{Vote: precommit.ToProto()}}},
		"p2p_has_vote":     {Sum: &cmtcons.Message_HasVote{HasVote: &cmtcons.HasVote{Height: height, Round: round, Type: cmtproto.PrecommitType, Index: 2}}},
		"p2p_vote_set_maj23": {Sum: &cmtcons.Message_VoteSetMaj23{VoteSetMaj23: &cmtcons.VoteSetMaj23{
			Height: height, Round: round, Type: cmtproto.PrecommitType, BlockID: blockID.ToProto(),
		}}},
		"p2p_vote_set_bits": {Sum: &cmtcons.Message_VoteSetBits{VoteSetBits: &cmtcons.VoteSetBits{
			Height: height, Round: round, Type: cmtproto.PrecommitType, BlockID: blockID.ToProto(), Votes: *bitArrayProto(4, 3),
		}}},
		"p2p_has_proposal_block_part": {Sum: &cmtcons.Message_HasProposalBlockPart{HasProposalBlockPart: &cmtcons.HasProposalBlockPart{
			Height: height + 1, Round: round, Index: 0,
		}}},
		"p2p_commit": {Sum: &cmtcons.Message_Commit{Commit: &cmtcons.Commit{Commit: aggCommit.ToProto()}}},
	}
	for name, m := range msgs {
		bz, err := m.Marshal()
		must(err)
		v[name] = hx(bz)
	}

	// ---- WAL -------------------------------------------------------------------
	walVote := &cmtcons.TimedWALMessage{
		Time: fixedTime,
		Msg: &cmtcons.WALMessage{Sum: &cmtcons.WALMessage_MsgInfo{MsgInfo: &cmtcons.MsgInfo{
			Msg:    *msgs["p2p_vote"],
			PeerID: "",
		}}},
	}
	bz, err = walVote.Marshal()
	must(err)
	v["wal_msginfo_vote_proto"] = hx(bz)
	walProposalRT := &cmtcons.TimedWALMessage{
		Time: fixedTime,
		Msg: &cmtcons.WALMessage{Sum: &cmtcons.WALMessage_MsgInfo{MsgInfo: &cmtcons.MsgInfo{
			Msg:         *msgs["p2p_proposal"],
			PeerID:      "peer1",
			ReceiveTime: &fixedTimeNext,
		}}},
	}
	bz, err = walProposalRT.Marshal()
	must(err)
	v["wal_msginfo_proposal_with_receive_time_proto"] = hx(bz)
	walTimeout := &cmtcons.TimedWALMessage{
		Time: fixedTime,
		Msg: &cmtcons.WALMessage{Sum: &cmtcons.WALMessage_TimeoutInfo{TimeoutInfo: &cmtcons.TimeoutInfo{
			Duration: 3 * time.Second, Height: height, Round: round, Step: 4,
		}}},
	}
	bz, err = walTimeout.Marshal()
	must(err)
	v["wal_timeout_proto"] = hx(bz)
	walEnd := &cmtcons.TimedWALMessage{
		Time: fixedTime,
		Msg:  &cmtcons.WALMessage{Sum: &cmtcons.WALMessage_EndHeight{EndHeight: &cmtcons.EndHeight{Height: height}}},
	}
	bz, err = walEnd.Marshal()
	must(err)
	v["wal_end_height_proto"] = hx(bz)
	walRS := &cmtcons.TimedWALMessage{
		Time: fixedTime,
		Msg: &cmtcons.WALMessage{Sum: &cmtcons.WALMessage_EventDataRoundState{EventDataRoundState: &cmtproto.EventDataRoundState{
			Height: height, Round: round, Step: "RoundStepPropose",
		}}},
	}
	bz, err = walRS.Marshal()
	must(err)
	v["wal_event_round_state_proto"] = hx(bz)

	// ---- genesis & privval files --------------------------------------------------
	genDoc := types.GenesisDoc{
		GenesisTime:     fixedTime,
		ChainID:         chainID,
		InitialHeight:   1,
		ConsensusParams: &params,
		AppHash:         h32("genesis-app"),
		AppState:        json.RawMessage(`{"k":"v"}`),
	}
	for i := 0; i < numVals; i++ {
		genDoc.Validators = append(genDoc.Validators, types.GenesisValidator{
			Address: blsVals[i].Address, PubKey: blsVals[i].PubKey, Power: blsVals[i].VotingPower, Name: fmt.Sprintf("val%d", i),
		})
	}
	must(genDoc.ValidateAndComplete())
	tmp, err := os.MkdirTemp("", "bera-compat-gen")
	must(err)
	defer os.RemoveAll(tmp)
	genFile := filepath.Join(tmp, "genesis.json")
	must(genDoc.SaveAs(genFile))
	bz, err = os.ReadFile(genFile)
	must(err)
	v["genesis_json"] = string(bz)
	v["genesis_validator_hash"] = hx(genDoc.ValidatorHash())

	keyFile := filepath.Join(tmp, "priv_validator_key.json")
	stateFile := filepath.Join(tmp, "priv_validator_state.json")
	pv := privval.NewFilePV(blsPrivs[0], keyFile, stateFile)
	pv.Save()
	bz, err = os.ReadFile(keyFile)
	must(err)
	v["priv_validator_key_json"] = string(bz)
	bz, err = os.ReadFile(stateFile)
	must(err)
	v["priv_validator_state_json"] = string(bz)
	pvProp := types.NewProposal(height, round, -1, blockID, fixedTime).ToProto()
	must(pv.SignProposal(chainID, pvProp))
	v["privval_signed_proposal_signature"] = hx(pvProp.Signature)
	pvVote := mkVote(types.PrecommitType, blockID, 0, blsVals[0].Address).ToProto()
	must(pv.SignVote(chainID, pvVote, false))
	v["privval_signed_vote_signature"] = hx(pvVote.Signature)
	v["privval_signed_vote_proto"] = hx(mustMarshal(pvVote))
	bz, err = os.ReadFile(stateFile)
	must(err)
	v["priv_validator_state_json_after_signing"] = string(bz)
	pvKey, err := pv.GetPubKey()
	must(err)
	v["privval_pubkey"] = hx(pvKey.Bytes())
	// priv key JSON via cmtjson (as used by the key file) and raw bytes
	bz, err = cmtjson.Marshal(blsPrivs[0])
	must(err)
	v["bls_privkey0_cmtjson"] = string(bz)
	v["bls_privkey0_bytes"] = hx(blsPrivs[0].Bytes())
	pvEd := privval.NewFilePV(edPriv, filepath.Join(tmp, "ed.json"), filepath.Join(tmp, "ed_state.json"))
	pvEd.Save()
	bz, err = os.ReadFile(filepath.Join(tmp, "ed.json"))
	must(err)
	v["priv_validator_key_ed25519_json"] = string(bz)

	// ---- aggregation primitives ---------------------------------------------------
	msg := []byte("bera-compat-aggregate-message")
	sigs := make([][]byte, numVals)
	pubs := make([]*bls12381.PubKey, numVals)
	for i := 0; i < numVals; i++ {
		sigs[i], err = blsPrivs[i].Sign(msg)
		must(err)
		pubs[i] = blsPubPtr(blsPrivs[i].PubKey())
	}
	agg, err := bls12381.AggregateSignatures(sigs)
	must(err)
	if !bls12381.VerifyAggregateSignature(agg, pubs, msg) {
		panic("aggregate does not verify")
	}
	v["bls_aggregate_signature"] = hx(agg)
	v["bls_aggregate_message"] = string(msg)

	v["_source"] = "generated by test/compat/gen-v1x against bera-v1.x"
	return v
}

// verify loads the values produced by bera-v0.40.x for the same inputs and
// checks, with bera-v1.x code, that (a) every shared value is byte-identical
// and (b) the fork-specific artifacts decode and validate here. It prints a
// report and returns a process exit code.
func verify(v out, path string) int {
	bz, err := os.ReadFile(path)
	must(err)
	port := map[string]any{}
	must(json.Unmarshal(bz, &port))
	fails := 0
	fail := func(format string, args ...any) {
		fails++
		fmt.Printf("FAIL: "+format+"\n", args...)
	}
	ok := func(format string, args ...any) { fmt.Printf("ok:   "+format+"\n", args...) }

	// (a) shared values must be identical
	shared := 0
	for k, pv := range port {
		if strings.HasPrefix(k, "_") || strings.HasPrefix(k, "v040_") {
			continue
		}
		mine, exists := v[k]
		if !exists {
			fail("%s: produced by bera-v0.40.x but unknown to bera-v1.x generator", k)
			continue
		}
		shared++
		if k == "params_json" {
			// bera-v0.40.x carries upstream's extra "authority" consensus-param
			// object; everything bera-v1.x knows must match and the extra must be
			// empty (bera-v1.x ignores unknown keys, as the genesis check below shows).
			var got map[string]json.RawMessage
			if err := json.Unmarshal([]byte(fmt.Sprint(pv)), &got); err != nil {
				fail("params_json: %v", err)
				continue
			}
			if string(got["authority"]) != `{"authority":""}` {
				fail("params_json: unexpected authority value %s", got["authority"])
			}
			delete(got, "authority")
			stripped, _ := json.Marshal(got)
			var mineMap map[string]json.RawMessage
			must(json.Unmarshal([]byte(fmt.Sprint(mine)), &mineMap))
			mineBz, _ := json.Marshal(mineMap)
			if string(stripped) != string(mineBz) {
				fail("params_json: differs beyond the authority object\n  bera-v1.x:   %s\n  bera-v0.40.x: %s", mineBz, stripped)
			}
			continue
		}
		if fmt.Sprint(mine) != fmt.Sprint(pv) {
			fail("%s: differs\n  bera-v1.x:   %v\n  bera-v0.40.x: %v", k, mine, pv)
		}
	}
	ok("%d shared values byte-identical (unless listed above)", shared)

	hexOf := func(k string) []byte {
		s, _ := port[k].(string)
		b, err := hex.DecodeString(s)
		if err != nil {
			fail("%s: not hex: %v", k, err)
		}
		return b
	}
	strOf := func(k string) string { s, _ := port[k].(string); return s }
	f := fixtureFor(v)

	// (b) fork-specific artifacts decode with bera-v1.x code
	// FinalizeBlock response as persisted by bera-v0.40.x: validator updates
	// must decode with the public key (pub_key_bytes/pub_key_type), and the
	// extra pub_key field (reserved here) must be skipped.
	{
		info := new(cmtstate.ABCIResponsesInfo)
		if err := info.Unmarshal(hexOf("v040_abci_responses_info_proto")); err != nil {
			fail("v040_abci_responses_info_proto: decode: %v", err)
		} else if info.FinalizeBlock == nil || len(info.FinalizeBlock.ValidatorUpdates) != 1 {
			fail("v040_abci_responses_info_proto: missing finalize block / validator updates")
		} else {
			fb := info.FinalizeBlock
			vals, err := types.PB2TM.ValidatorUpdates(fb.ValidatorUpdates)
			switch {
			case err != nil:
				fail("v040 validator updates: %v", err)
			case !bytes.Equal(vals[0].PubKey.Bytes(), f.blsVals[0].PubKey.Bytes()) || vals[0].VotingPower != 77:
				fail("v040 validator update decoded to wrong validator %v", vals[0])
			case fb.NextBlockDelay != 1500*time.Millisecond:
				fail("v040 next_block_delay = %v", fb.NextBlockDelay)
			case info.Height != height:
				fail("v040 abci responses height = %d", info.Height)
			default:
				upd := f.params.Update(fb.ConsensusParamUpdates)
				if hx(upd.Hash()) != v["params_updated_hash"] {
					fail("v040 consensus param update applies differently")
				} else {
					ok("bera-v0.40.x FinalizeBlock response decodes (validator update pubkey, next_block_delay, param update)")
				}
			}
		}
		fbr := new(abci.FinalizeBlockResponse)
		if err := fbr.Unmarshal(hexOf("v040_finalize_block_response_proto")); err != nil {
			fail("v040_finalize_block_response_proto: decode: %v", err)
		}
	}
	// genesis.json written by bera-v0.40.x (carries an extra "authority"
	// consensus-param object, which must be ignored here)
	{
		gd, err := types.GenesisDocFromJSON([]byte(strOf("v040_genesis_json")))
		switch {
		case err != nil:
			fail("v040_genesis_json: parse: %v", err)
		case gd.ValidateAndComplete() != nil:
			fail("v040_genesis_json: validate: %v", gd.ValidateAndComplete())
		case hx(gd.ValidatorHash()) != v["genesis_validator_hash"]:
			fail("v040_genesis_json: validator hash differs")
		case hx(gd.ConsensusParams.Hash()) != v["params_hash"]:
			fail("v040_genesis_json: consensus params hash differs")
		case gd.ChainID != chainID || !gd.GenesisTime.Equal(fixedTime):
			fail("v040_genesis_json: chain id / time differ")
		default:
			ok("bera-v0.40.x genesis.json parses (validator hash, params hash, chain id, time)")
		}
	}
	// privval key/state files written by bera-v0.40.x
	{
		tmp, err := os.MkdirTemp("", "bera-compat-verify")
		must(err)
		defer os.RemoveAll(tmp)
		kf, sf := filepath.Join(tmp, "k.json"), filepath.Join(tmp, "s.json")
		must(os.WriteFile(kf, []byte(strOf("v040_priv_validator_key_json")), 0o600))
		must(os.WriteFile(sf, []byte(strOf("v040_priv_validator_state_json")), 0o600))
		pv := privval.LoadFilePV(kf, sf)
		pub, err := pv.GetPubKey()
		if err != nil || !bytes.Equal(pub.Bytes(), f.blsVals[0].PubKey.Bytes()) {
			fail("v040 priv_validator_key.json: wrong key (%v)", err)
		} else {
			vote := &types.Vote{Type: types.PrecommitType, Height: height, Round: round, BlockID: f.blockID,
				ValidatorAddress: f.blsVals[0].Address, ValidatorIndex: 0}
			pb := vote.ToProto()
			if err := pv.SignVote(chainID, pb, false); err != nil {
				fail("v040 priv_validator_key.json: sign: %v", err)
			} else if hx(pb.Signature) != v["privval_signed_vote_signature"] {
				fail("v040 priv_validator_key.json: signature differs")
			} else {
				ok("bera-v0.40.x priv_validator_key.json loads and signs identically")
			}
		}
	}
	// consensus-critical bera-v0.40.x bytes decode and verify here
	{
		pc := new(cmtproto.Commit)
		if err := pc.Unmarshal(hexOf("agg_commit_proto")); err != nil {
			fail("agg_commit_proto: decode: %v", err)
		} else if c, err := types.CommitFromProto(pc); err != nil {
			fail("agg_commit_proto: from proto: %v", err)
		} else if err := f.blsValSet.VerifyCommit(chainID, f.blockID, height, c); err != nil {
			fail("agg_commit_proto: verify: %v", err)
		} else {
			ok("bera-v0.40.x aggregated commit verifies against the validator set")
		}
		pb := new(cmtproto.Block)
		if err := pb.Unmarshal(hexOf("block_proto")); err != nil {
			fail("block_proto: decode: %v", err)
		} else if b, err := types.BlockFromProto(pb); err != nil {
			fail("block_proto: from proto: %v", err)
		} else if err := b.ValidateBasic(); err != nil {
			fail("block_proto: validate: %v", err)
		} else if hx(b.Hash()) != v["block_hash"] {
			fail("block_proto: hash differs")
		} else {
			ok("bera-v0.40.x block decodes, validates and hashes identically")
		}
		pvt := new(cmtproto.Vote)
		if err := pvt.Unmarshal(hexOf("vote_proto_signed_precommit")); err != nil {
			fail("vote_proto_signed_precommit: decode: %v", err)
		} else if vt, err := types.VoteFromProto(pvt); err != nil {
			fail("vote_proto_signed_precommit: from proto: %v", err)
		} else if err := vt.Verify(chainID, f.blsVals[0].PubKey); err != nil {
			fail("vote_proto_signed_precommit: verify: %v", err)
		} else {
			ok("bera-v0.40.x signed precommit verifies")
		}
		ps := new(cmtstate.State)
		if err := ps.Unmarshal(hexOf("state_proto")); err != nil {
			fail("state_proto: decode: %v", err)
		} else if st, err := sm.FromProto(ps); err != nil {
			fail("state_proto: from proto: %v", err)
		} else if st.NextBlockDelay != 1500*time.Millisecond || st.LastBlockHeight != height || hx(st.ConsensusParams.Hash()) != v["params_hash"] {
			fail("state_proto: decoded state differs")
		} else {
			ok("bera-v0.40.x persisted state loads (next_block_delay, height, params)")
		}
		for _, k := range []string{"p2p_vote", "p2p_commit", "p2p_proposal", "p2p_block_part", "p2p_has_proposal_block_part", "p2p_new_round_step", "p2p_vote_set_bits"} {
			m := new(cmtcons.Message)
			if err := m.Unmarshal(hexOf(k)); err != nil {
				fail("%s: decode: %v", k, err)
			} else if re, err := m.Marshal(); err != nil || hx(re) != v[k] {
				fail("%s: does not round-trip", k)
			}
		}
		ok("bera-v0.40.x consensus p2p messages decode and round-trip")
		w := new(cmtcons.TimedWALMessage)
		if err := w.Unmarshal(hexOf("wal_msginfo_vote_proto")); err != nil {
			fail("wal_msginfo_vote_proto: decode: %v", err)
		} else {
			ok("bera-v0.40.x WAL entry decodes")
		}
	}

	if fails > 0 {
		fmt.Printf("\n%d failure(s)\n", fails)
		return 1
	}
	fmt.Println("\nall checks passed")
	return 0
}

// fixtureFor rebuilds the validator set and related inputs (same as generate).
type fixture struct {
	blsVals   []*types.Validator
	blsValSet *types.ValidatorSet
	blockID   types.BlockID
	params    types.ConsensusParams
}

func fixtureFor(_ out) *fixture {
	blsPrivs := make([]*bls12381.PrivKey, numVals)
	blsVals := make([]*types.Validator, numVals)
	for i := 0; i < numVals; i++ {
		pk, err := bls12381.GenPrivKeyFromSecret([]byte(fmt.Sprintf("%s%d", blsSeed, i)))
		must(err)
		blsPrivs[i] = pk
		blsVals[i] = types.NewValidator(pk.PubKey(), powers[i])
	}
	valSet := types.NewValidatorSet(blsVals)
	blsVals, _ = sortKeys(valSet, blsVals, blsPrivs)
	return &fixture{
		blsVals:   blsVals,
		blsValSet: valSet,
		blockID: types.BlockID{
			Hash:          h32("block"),
			PartSetHeader: types.PartSetHeader{Total: 3, Hash: h32("parts")},
		},
		params: consensusParams(),
	}
}

func durPtr(d time.Duration) *time.Duration { return &d }

func consensusParams() types.ConsensusParams {
	return types.ConsensusParams{
		Block:     types.BlockParams{MaxBytes: 104857600, MaxGas: -1},
		Evidence:  types.EvidenceParams{MaxAgeNumBlocks: 100000, MaxAgeDuration: 172800 * time.Second, MaxBytes: 1048576},
		Validator: types.ValidatorParams{PubKeyTypes: []string{types.ABCIPubKeyTypeBls12381}},
		Version:   types.VersionParams{App: 1},
		Synchrony: types.SynchronyParams{Precision: 505 * time.Millisecond, MessageDelay: 15 * time.Second},
		Feature:   types.FeatureParams{VoteExtensionsEnableHeight: 0, PbtsEnableHeight: 1, SBTEnableHeight: 7},
	}
}

// sortKeys reorders vals/privs to follow the order of the validators inside
// valSet (which sorts by voting power, then address).
func sortKeys[K any](valSet *types.ValidatorSet, vals []*types.Validator, privs []K) ([]*types.Validator, []K) {
	outVals := make([]*types.Validator, len(vals))
	outPrivs := make([]K, len(privs))
	for i, sv := range valSet.Validators {
		found := false
		for j, v := range vals {
			if bytes.Equal(v.PubKey.Bytes(), sv.PubKey.Bytes()) {
				outVals[i] = sv
				outPrivs[i] = privs[j]
				found = true
				break
			}
		}
		if !found {
			panic("validator not found")
		}
	}
	return outVals, outPrivs
}

// blsPubPtr returns the BLS public key as a pointer regardless of whether the
// crypto.PubKey holds a value or a pointer.
func blsPubPtr(pk crypto.PubKey) *bls12381.PubKey {
	switch k := pk.(type) {
	case *bls12381.PubKey:
		return k
	case bls12381.PubKey:
		return &k
	default:
		panic(fmt.Sprintf("not a BLS public key: %T", pk))
	}
}

func compress(pk crypto.PubKey) []byte { return blsPubPtr(pk).Compress() }

func mustMarshal(m interface{ Marshal() ([]byte, error) }) []byte {
	bz, err := m.Marshal()
	must(err)
	return bz
}

// bitArrayProto builds the proto form of a bits.BitArray of n bits with a
// single bit set at index set (libs/bits is internal on bera-v1.x).
func bitArrayProto(n int, set int) *cmtbits.BitArray {
	elems := make([]uint64, (n+63)/64)
	elems[set/64] |= 1 << (uint(set) % 64)
	return &cmtbits.BitArray{Bits: int64(n), Elems: elems}
}
