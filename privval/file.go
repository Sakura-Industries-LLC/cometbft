package privval

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cosmos/gogoproto/proto"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/secp256k1"
	cmtbytes "github.com/cometbft/cometbft/libs/bytes"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	cmtos "github.com/cometbft/cometbft/libs/os"
	"github.com/cometbft/cometbft/libs/protoio"
	"github.com/cometbft/cometbft/libs/tempfile"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
	cmttime "github.com/cometbft/cometbft/types/time"
)

// TODO: type ?
const (
	stepNone      int8 = 0 // Used to distinguish the initial state
	stepPropose   int8 = 1
	stepPrevote   int8 = 2
	stepPrecommit int8 = 3
)

// A vote is either stepPrevote or stepPrecommit.
func voteToStep(vote *cmtproto.Vote) int8 {
	switch vote.Type {
	case cmtproto.PrevoteType:
		return stepPrevote
	case cmtproto.PrecommitType:
		return stepPrecommit
	default:
		panic(fmt.Sprintf("Unknown vote type: %v", vote.Type))
	}
}

//-------------------------------------------------------------------------------

// FilePVKey stores the immutable part of PrivValidator.
type FilePVKey struct {
	Address types.Address  `json:"address"`
	PubKey  crypto.PubKey  `json:"pub_key"`
	PrivKey crypto.PrivKey `json:"priv_key"`

	filePath string
}

// Save persists the FilePVKey to its filePath.
func (pvKey FilePVKey) Save() {
	outFile := pvKey.filePath
	if outFile == "" {
		panic("cannot save PrivValidator key: filePath not set")
	}

	jsonBytes, err := cmtjson.MarshalIndent(pvKey, "", "  ")
	if err != nil {
		panic(err)
	}

	if err := tempfile.WriteFileAtomic(outFile, jsonBytes, 0o600); err != nil {
		panic(err)
	}
}

//-------------------------------------------------------------------------------

// FilePVLastSignState stores the mutable part of PrivValidator.
type FilePVLastSignState struct {
	Height    int64             `json:"height"`
	Round     int32             `json:"round"`
	Step      int8              `json:"step"`
	Signature []byte            `json:"signature,omitempty"`
	SignBytes cmtbytes.HexBytes `json:"signbytes,omitempty"`

	filePath string
}

func (lss *FilePVLastSignState) reset() {
	lss.Height = 0
	lss.Round = 0
	lss.Step = 0
	lss.Signature = nil
	lss.SignBytes = nil
}

// CheckHRS checks the given height, round, step (HRS) against that of the
// FilePVLastSignState. It returns an error if the arguments constitute a regression,
// or if they match but the SignBytes are empty.
// The returned boolean indicates whether the last Signature should be reused -
// it returns true if the HRS matches the arguments and the SignBytes are not empty (indicating
// we have already signed for this HRS, and can reuse the existing signature).
// It panics if the HRS matches the arguments, there's a SignBytes, but no Signature.
func (lss *FilePVLastSignState) CheckHRS(height int64, round int32, step int8) (bool, error) {
	if lss.Height > height {
		return false, fmt.Errorf("height regression. Got %v, last height %v", height, lss.Height)
	}

	if lss.Height == height {
		if lss.Round > round {
			return false, fmt.Errorf("round regression at height %v. Got %v, last round %v", height, round, lss.Round)
		}

		if lss.Round == round {
			if lss.Step > step {
				return false, fmt.Errorf(
					"step regression at height %v round %v. Got %v, last step %v",
					height,
					round,
					step,
					lss.Step,
				)
			} else if lss.Step == step {
				if lss.SignBytes != nil {
					if lss.Signature == nil {
						panic("pv: Signature is nil but SignBytes is not!")
					}
					return true, nil
				}
				return false, errors.New("no SignBytes found")
			}
		}
	}
	return false, nil
}

// Save persists the FilePvLastSignState to its filePath.
func (lss *FilePVLastSignState) Save() {
	outFile := lss.filePath
	if outFile == "" {
		panic("cannot save FilePVLastSignState: filePath not set")
	}
	jsonBytes, err := cmtjson.MarshalIndent(lss, "", "  ")
	if err != nil {
		panic(err)
	}
	err = tempfile.WriteFileAtomic(outFile, jsonBytes, 0o600)
	if err != nil {
		panic(err)
	}
}

//-------------------------------------------------------------------------------

// FilePV implements PrivValidator using data persisted to disk
// to prevent double signing.
// NOTE: the directories containing pv.Key.filePath and pv.LastSignState.filePath must already exist.
// It includes the LastSignature and LastSignBytes so we don't lose the signature
// if the process crashes after signing but before the resulting consensus message is processed.
type FilePV struct {
	Key           FilePVKey
	LastSignState FilePVLastSignState
}

// NewFilePV generates a new validator from the given key and paths.
func NewFilePV(privKey crypto.PrivKey, keyFilePath, stateFilePath string) *FilePV {
	return &FilePV{
		Key: FilePVKey{
			Address:  privKey.PubKey().Address(),
			PubKey:   privKey.PubKey(),
			PrivKey:  privKey,
			filePath: keyFilePath,
		},
		LastSignState: FilePVLastSignState{
			Step:     stepNone,
			filePath: stateFilePath,
		},
	}
}

// GenFilePV generates a new validator with randomly generated private key
// and sets the filePaths, but does not call Save().
func GenFilePV(keyFilePath, stateFilePath string) *FilePV {
	return NewFilePV(ed25519.GenPrivKey(), keyFilePath, stateFilePath)
}

// LoadFilePV loads a FilePV from the file paths. The FilePV prevents double
// signing by persisting data to stateFilePath. The program exits if either
// file cannot be loaded.
func LoadFilePV(keyFilePath, stateFilePath string) *FilePV {
	return loadFilePV(keyFilePath, stateFilePath, true)
}

// LoadFilePVWithError loads a FilePV from the file paths without terminating
// the process when a file is missing or invalid.
func LoadFilePVWithError(keyFilePath, stateFilePath string) (*FilePV, error) {
	return loadFilePVWithError(keyFilePath, stateFilePath, true)
}

// LoadFilePVEmptyState loads a FilePV from keyFilePath with an empty
// LastSignState. The program exits if the key file cannot be loaded.
func LoadFilePVEmptyState(keyFilePath, stateFilePath string) *FilePV {
	return loadFilePV(keyFilePath, stateFilePath, false)
}

// loadFilePV loads a FilePV or exits the process.
func loadFilePV(keyFilePath, stateFilePath string, loadState bool) *FilePV {
	pv, err := loadFilePVWithError(keyFilePath, stateFilePath, loadState)
	if err != nil {
		cmtos.Exit(err.Error())
	}
	return pv
}

// loadFilePVWithError loads a FilePV and returns file and decoding errors.
func loadFilePVWithError(keyFilePath, stateFilePath string, loadState bool) (*FilePV, error) {
	keyJSONBytes, err := os.ReadFile(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("read private validator key %q: %w", keyFilePath, err)
	}
	pvKey := FilePVKey{}
	if err := cmtjson.Unmarshal(keyJSONBytes, &pvKey); err != nil {
		return nil, fmt.Errorf("decode private validator key %q: %w", keyFilePath, err)
	}
	if pvKey.PrivKey == nil {
		return nil, fmt.Errorf("decode private validator key %q: private key is missing", keyFilePath)
	}

	// Overwrite the public key and address from the private key.
	pubKey, err := derivePubKey(pvKey.PrivKey)
	if err != nil {
		return nil, fmt.Errorf("decode private validator key %q: %w", keyFilePath, err)
	}
	pvKey.PubKey = pubKey
	pvKey.Address = pubKey.Address()
	pvKey.filePath = keyFilePath

	pvState := FilePVLastSignState{}
	if loadState {
		stateJSONBytes, err := os.ReadFile(stateFilePath)
		if err != nil {
			return nil, fmt.Errorf("read private validator state %q: %w", stateFilePath, err)
		}
		if err := cmtjson.Unmarshal(stateJSONBytes, &pvState); err != nil {
			return nil, fmt.Errorf("decode private validator state %q: %w", stateFilePath, err)
		}
	}
	pvState.filePath = stateFilePath

	return &FilePV{
		Key:           pvKey,
		LastSignState: pvState,
	}, nil
}

// derivePubKey validates private key material and returns its public key,
// converting implementation panics on malformed bytes into an error.
func derivePubKey(privKey crypto.PrivKey) (pubKey crypto.PubKey, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			pubKey = nil
			err = fmt.Errorf("invalid private key material: %v", recovered)
		}
	}()

	switch key := privKey.(type) {
	case ed25519.PrivKey:
		if len(key) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid Ed25519 private key size: got %d, want %d", len(key), ed25519.PrivateKeySize)
		}
	case secp256k1.PrivKey:
		if len(key) != secp256k1.PrivKeySize {
			return nil, fmt.Errorf("invalid secp256k1 private key size: got %d, want %d", len(key), secp256k1.PrivKeySize)
		}
	}

	pubKey = privKey.PubKey()
	if pubKey == nil {
		return nil, errors.New("private key returned a nil public key")
	}
	message := []byte("CometBFT private validator key validation")
	signature, err := privKey.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("sign validation message: %w", err)
	}
	if !pubKey.VerifySignature(message, signature) {
		return nil, errors.New("private key failed self-verification")
	}
	return pubKey, nil
}

// LoadOrGenFilePV loads a FilePV from the given filePaths
// or else generates a new one and saves it to the filePaths.
func LoadOrGenFilePV(keyFilePath, stateFilePath string) *FilePV {
	var pv *FilePV
	if cmtos.FileExists(keyFilePath) {
		pv = LoadFilePV(keyFilePath, stateFilePath)
	} else {
		pv = GenFilePV(keyFilePath, stateFilePath)
		pv.Save()
	}
	return pv
}

// GetAddress returns the address of the validator.
// Implements PrivValidator.
func (pv *FilePV) GetAddress() types.Address {
	return pv.Key.Address
}

// GetPubKey returns the public key of the validator.
// Implements PrivValidator.
func (pv *FilePV) GetPubKey() (crypto.PubKey, error) {
	return pv.Key.PubKey, nil
}

// SignVote signs a canonical representation of the vote, along with the
// chainID. Implements PrivValidator.
func (pv *FilePV) SignVote(chainID string, vote *cmtproto.Vote) error {
	if err := pv.signVote(chainID, vote); err != nil {
		return fmt.Errorf("error signing vote: %v", err)
	}
	return nil
}

// SignProposal signs a canonical representation of the proposal, along with
// the chainID. Implements PrivValidator.
func (pv *FilePV) SignProposal(chainID string, proposal *cmtproto.Proposal) error {
	if err := pv.signProposal(chainID, proposal); err != nil {
		return fmt.Errorf("error signing proposal: %v", err)
	}
	return nil
}

// Save persists the FilePV to disk.
func (pv *FilePV) Save() {
	pv.Key.Save()
	pv.LastSignState.Save()
}

// Reset resets all fields in the FilePV.
// NOTE: Unsafe!
func (pv *FilePV) Reset() {
	pv.LastSignState.reset()
	pv.Save()
}

// String returns a string representation of the FilePV.
func (pv *FilePV) String() string {
	return fmt.Sprintf(
		"PrivValidator{%v LH:%v, LR:%v, LS:%v}",
		pv.GetAddress(),
		pv.LastSignState.Height,
		pv.LastSignState.Round,
		pv.LastSignState.Step,
	)
}

//------------------------------------------------------------------------------------

// signVote checks if the vote is good to sign and sets the vote signature.
// It may need to set the timestamp as well if the vote is otherwise the same as
// a previously signed vote (ie. we crashed after signing but before the vote hit the WAL).
// Extension signatures are always signed for non-nil precommits (even if the data is empty).
func (pv *FilePV) signVote(chainID string, vote *cmtproto.Vote) error {
	height, round, step := vote.Height, vote.Round, voteToStep(vote)

	lss := pv.LastSignState

	sameHRS, err := lss.CheckHRS(height, round, step)
	if err != nil {
		return err
	}

	signBytes := types.VoteSignBytes(chainID, vote)

	// Vote extensions are non-deterministic, so it is possible that an
	// application may have created a different extension. We therefore always
	// re-sign the vote extensions of precommits. For prevotes and nil
	// precommits, the extension signature will always be empty.
	// Even if the signed over data is empty, we still add the signature
	var extSig []byte
	if vote.Type == cmtproto.PrecommitType && !types.ProtoBlockIDIsNil(&vote.BlockID) {
		extSignBytes := types.VoteExtensionSignBytes(chainID, vote)
		extSig, err = pv.Key.PrivKey.Sign(extSignBytes)
		if err != nil {
			return err
		}
	} else if len(vote.Extension) > 0 {
		return errors.New("unexpected vote extension - extensions are only allowed in non-nil precommits")
	}

	// We might crash before writing to the wal,
	// causing us to try to re-sign for the same HRS.
	// If signbytes are the same, use the last signature.
	// If they only differ by timestamp, use last timestamp and signature
	// Otherwise, return error
	if sameHRS {
		if bytes.Equal(signBytes, lss.SignBytes) {
			vote.Signature = lss.Signature
		} else if timestamp, ok := checkVotesOnlyDifferByTimestamp(lss.SignBytes, signBytes); ok {
			// Compares the canonicalized votes (i.e. without vote extensions
			// or vote extension signatures).
			vote.Timestamp = timestamp
			vote.Signature = lss.Signature
		} else {
			err = fmt.Errorf("conflicting data")
		}

		vote.ExtensionSignature = extSig

		return err
	}

	// It passed the checks. Sign the vote
	sig, err := pv.Key.PrivKey.Sign(signBytes)
	if err != nil {
		return err
	}
	pv.saveSigned(height, round, step, signBytes, sig)
	vote.Signature = sig
	vote.ExtensionSignature = extSig

	return nil
}

// signProposal checks if the proposal is good to sign and sets the proposal signature.
// It may need to set the timestamp as well if the proposal is otherwise the same as
// a previously signed proposal ie. we crashed after signing but before the proposal hit the WAL).
func (pv *FilePV) signProposal(chainID string, proposal *cmtproto.Proposal) error {
	height, round, step := proposal.Height, proposal.Round, stepPropose

	lss := pv.LastSignState

	sameHRS, err := lss.CheckHRS(height, round, step)
	if err != nil {
		return err
	}

	signBytes := types.ProposalSignBytes(chainID, proposal)

	// We might crash before writing to the wal,
	// causing us to try to re-sign for the same HRS.
	// If signbytes are the same, use the last signature.
	// If they only differ by timestamp, use last timestamp and signature
	// Otherwise, return error
	if sameHRS {
		if bytes.Equal(signBytes, lss.SignBytes) {
			proposal.Signature = lss.Signature
		} else if timestamp, ok := checkProposalsOnlyDifferByTimestamp(lss.SignBytes, signBytes); ok {
			proposal.Timestamp = timestamp
			proposal.Signature = lss.Signature
		} else {
			err = fmt.Errorf("conflicting data")
		}
		return err
	}

	// It passed the checks. Sign the proposal
	sig, err := pv.Key.PrivKey.Sign(signBytes)
	if err != nil {
		return err
	}
	pv.saveSigned(height, round, step, signBytes, sig)
	proposal.Signature = sig
	return nil
}

// Persist height/round/step and signature
func (pv *FilePV) saveSigned(height int64, round int32, step int8,
	signBytes []byte, sig []byte,
) {
	pv.LastSignState.Height = height
	pv.LastSignState.Round = round
	pv.LastSignState.Step = step
	pv.LastSignState.Signature = sig
	pv.LastSignState.SignBytes = signBytes
	pv.LastSignState.Save()
}

//-----------------------------------------------------------------------------------------

// Returns the timestamp from the lastSignBytes.
// Returns true if the only difference in the votes is their timestamp.
// Performs these checks on the canonical votes (excluding the vote extension
// and vote extension signatures).
func checkVotesOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) (time.Time, bool) {
	var lastVote, newVote cmtproto.CanonicalVote
	if err := protoio.UnmarshalDelimited(lastSignBytes, &lastVote); err != nil {
		panic(fmt.Sprintf("LastSignBytes cannot be unmarshalled into vote: %v", err))
	}
	if err := protoio.UnmarshalDelimited(newSignBytes, &newVote); err != nil {
		panic(fmt.Sprintf("signBytes cannot be unmarshalled into vote: %v", err))
	}

	lastTime := lastVote.Timestamp
	// set the times to the same value and check equality
	now := cmttime.Now()
	lastVote.Timestamp = now
	newVote.Timestamp = now

	return lastTime, proto.Equal(&newVote, &lastVote)
}

// returns the timestamp from the lastSignBytes.
// returns true if the only difference in the proposals is their timestamp
func checkProposalsOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) (time.Time, bool) {
	var lastProposal, newProposal cmtproto.CanonicalProposal
	if err := protoio.UnmarshalDelimited(lastSignBytes, &lastProposal); err != nil {
		panic(fmt.Sprintf("LastSignBytes cannot be unmarshalled into proposal: %v", err))
	}
	if err := protoio.UnmarshalDelimited(newSignBytes, &newProposal); err != nil {
		panic(fmt.Sprintf("signBytes cannot be unmarshalled into proposal: %v", err))
	}

	lastTime := lastProposal.Timestamp
	// set the times to the same value and check equality
	now := cmttime.Now()
	lastProposal.Timestamp = now
	newProposal.Timestamp = now

	return lastTime, proto.Equal(&newProposal, &lastProposal)
}
