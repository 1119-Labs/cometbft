package types

import (
	"errors"
	"fmt"
	"time"

	cmtbytes "github.com/cometbft/cometbft/libs/bytes"
	"github.com/cometbft/cometbft/libs/protoio"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttime "github.com/cometbft/cometbft/types/time"
)

var (
	ErrInvalidBlockPartSignature = errors.New("error invalid block part signature")
	ErrInvalidBlockPartHash      = errors.New("error invalid block part hash")
)

// Proposal defines a block proposal for the consensus.
// It refers to the block by BlockID field.
// It must be signed by the correct proposer for the given Height/Round
// to be considered valid. It may depend on votes from a previous round,
// a so-called Proof-of-Lock (POL) round, as noted in the POLRound.
// If POLRound >= 0, then BlockID corresponds to the block that is locked in POLRound.
type Proposal struct {
	Type      cmtproto.SignedMsgType
	Height    int64     `json:"height"`
	Round     int32     `json:"round"`     // there can not be greater than 2_147_483_647 rounds
	POLRound  int32     `json:"pol_round"` // -1 if null.
	BlockID   BlockID   `json:"block_id"`
	Timestamp time.Time `json:"timestamp"`
	Signature []byte    `json:"signature"`

	// Compact block data (optional, backward compatible).
	// NOT included in CanonicalProposal — signing is unaffected.
	TxKeys            []TxKey      `json:"tx_keys,omitempty"`
	NonMempoolTxs     []Tx         `json:"non_mempool_txs,omitempty"`
	NonMempoolIndices []int32      `json:"non_mempool_indices,omitempty"`
	CompactHeader     *Header      `json:"compact_header,omitempty"`
	CompactLastCommit *Commit      `json:"compact_last_commit,omitempty"`
	CompactEvidence   EvidenceData `json:"compact_evidence,omitempty"`
	ProposerAddress   Address      `json:"proposer_address,omitempty"`
}

// NewProposal returns a new Proposal.
// If there is no POLRound, polRound should be -1.
func NewProposal(height int64, round int32, polRound int32, blockID BlockID) *Proposal {
	return &Proposal{
		Type:      cmtproto.ProposalType,
		Height:    height,
		Round:     round,
		BlockID:   blockID,
		POLRound:  polRound,
		Timestamp: cmttime.Now(),
	}
}

// HasCompactData returns true if the proposal contains compact block data.
func (p *Proposal) HasCompactData() bool {
	return p.CompactHeader != nil && len(p.TxKeys) > 0
}

// headerFromProtoNoValidate converts a proto Header to a native Header without
// calling ValidateBasic(). The reconstructed block will be validated separately.
func headerFromProtoNoValidate(ph *cmtproto.Header) Header {
	var h Header
	if ph == nil {
		return h
	}
	bi, err := BlockIDFromProto(&ph.LastBlockId)
	if err != nil {
		bi = &BlockID{}
	}
	h.Version = ph.Version
	h.ChainID = ph.ChainID
	h.Height = ph.Height
	h.Time = ph.Time
	h.LastBlockID = *bi
	h.ValidatorsHash = ph.ValidatorsHash
	h.NextValidatorsHash = ph.NextValidatorsHash
	h.ConsensusHash = ph.ConsensusHash
	h.AppHash = ph.AppHash
	h.DataHash = ph.DataHash
	h.EvidenceHash = ph.EvidenceHash
	h.LastResultsHash = ph.LastResultsHash
	h.LastCommitHash = ph.LastCommitHash
	h.ProposerAddress = ph.ProposerAddress
	return h
}

// ValidateBasic performs basic validation.
func (p *Proposal) ValidateBasic() error {
	if p.Type != cmtproto.ProposalType {
		return errors.New("invalid Type")
	}
	if p.Height < 0 {
		return errors.New("negative Height")
	}
	if p.Round < 0 {
		return errors.New("negative Round")
	}
	if p.POLRound < -1 {
		return errors.New("negative POLRound (exception: -1)")
	}
	if err := p.BlockID.ValidateBasic(); err != nil {
		return fmt.Errorf("wrong BlockID: %v", err)
	}
	// ValidateBasic above would pass even if the BlockID was empty:
	if !p.BlockID.IsComplete() {
		return fmt.Errorf("expected a complete, non-empty BlockID, got: %v", p.BlockID)
	}

	// NOTE: Timestamp validation is subtle and handled elsewhere.

	if len(p.Signature) == 0 {
		return errors.New("signature is missing")
	}

	if len(p.Signature) > MaxSignatureSize {
		return fmt.Errorf("signature is too big (max: %d)", MaxSignatureSize)
	}
	return nil
}

// ValidateBlockSize block size ensures that a proposal block is not larger
// than a maximum number of bytes, based on the total amount of parts reported
// in the PartSetHeader. If -1 is passed as the maxBlockSizeBytes,
// types.MaxBlockSizeBytes will be used as the maximum.
func (p *Proposal) ValidateBlockSize(maxBlockSizeBytes int64) error {
	if maxBlockSizeBytes == -1 {
		maxBlockSizeBytes = int64(MaxBlockSizeBytes)
	}
	totalParts := int64(p.BlockID.PartSetHeader.Total)
	maxParts := (maxBlockSizeBytes-1)/int64(BlockPartSizeBytes) + 1
	if totalParts > maxParts {
		return fmt.Errorf("proposal has too many parts %d (max: %d)", totalParts, maxParts)
	}
	return nil
}

// String returns a string representation of the Proposal.
//
// 1. height
// 2. round
// 3. block ID
// 4. POL round
// 5. first 6 bytes of signature
// 6. timestamp
//
// See BlockID#String.
func (p *Proposal) String() string {
	return fmt.Sprintf("Proposal{%v/%v (%v, %v) %X @ %s}",
		p.Height,
		p.Round,
		p.BlockID,
		p.POLRound,
		cmtbytes.Fingerprint(p.Signature),
		CanonicalTime(p.Timestamp))
}

// ProposalSignBytes returns the proto-encoding of the canonicalized Proposal,
// for signing. Panics if the marshaling fails.
//
// The encoded Protobuf message is varint length-prefixed (using MarshalDelimited)
// for backwards-compatibility with the Amino encoding, due to e.g. hardware
// devices that rely on this encoding.
//
// See CanonicalizeProposal
func ProposalSignBytes(chainID string, p *cmtproto.Proposal) []byte {
	pb := CanonicalizeProposal(chainID, p)
	bz, err := protoio.MarshalDelimited(&pb)
	if err != nil {
		panic(err)
	}

	return bz
}

// ToProto converts Proposal to protobuf
func (p *Proposal) ToProto() *cmtproto.Proposal {
	if p == nil {
		return &cmtproto.Proposal{}
	}
	pb := new(cmtproto.Proposal)

	pb.BlockID = p.BlockID.ToProto()
	pb.Type = p.Type
	pb.Height = p.Height
	pb.Round = p.Round
	pb.PolRound = p.POLRound
	pb.Timestamp = p.Timestamp
	pb.Signature = p.Signature

	// Compact block fields
	if len(p.TxKeys) > 0 {
		pb.TxKeys = make([][]byte, len(p.TxKeys))
		for i, key := range p.TxKeys {
			k := key // copy
			pb.TxKeys[i] = k[:]
		}
	}
	if len(p.NonMempoolTxs) > 0 {
		pb.NonMempoolTxs = make([][]byte, len(p.NonMempoolTxs))
		for i, tx := range p.NonMempoolTxs {
			pb.NonMempoolTxs[i] = tx
		}
	}
	pb.NonMempoolIndices = p.NonMempoolIndices
	if p.CompactHeader != nil {
		pb.CompactHeader = p.CompactHeader.ToProto()
	}
	if p.CompactLastCommit != nil {
		pb.CompactLastCommit = p.CompactLastCommit.ToProto()
	}
	pb.ProposerAddress = p.ProposerAddress
	if len(p.CompactEvidence.Evidence) > 0 {
		evProto, err := p.CompactEvidence.ToProto()
		if err == nil {
			evBytes, err := evProto.Marshal()
			if err == nil {
				pb.CompactEvidence = evBytes
			}
		}
	}

	return pb
}

// FromProto sets a protobuf Proposal to the given pointer.
// It returns an error if the proposal is invalid.
func ProposalFromProto(pp *cmtproto.Proposal) (*Proposal, error) {
	if pp == nil {
		return nil, errors.New("nil proposal")
	}

	p := new(Proposal)

	blockID, err := BlockIDFromProto(&pp.BlockID)
	if err != nil {
		return nil, err
	}

	p.BlockID = *blockID
	p.Type = pp.Type
	p.Height = pp.Height
	p.Round = pp.Round
	p.POLRound = pp.PolRound
	p.Timestamp = pp.Timestamp
	p.Signature = pp.Signature

	// Compact block fields
	if len(pp.TxKeys) > 0 {
		p.TxKeys = make([]TxKey, len(pp.TxKeys))
		for i, keyBytes := range pp.TxKeys {
			if len(keyBytes) == TxKeySize {
				copy(p.TxKeys[i][:], keyBytes)
			}
		}
	}
	if len(pp.NonMempoolTxs) > 0 {
		p.NonMempoolTxs = make([]Tx, len(pp.NonMempoolTxs))
		for i, tx := range pp.NonMempoolTxs {
			p.NonMempoolTxs[i] = tx
		}
	}
	p.NonMempoolIndices = pp.NonMempoolIndices
	if pp.CompactHeader != nil {
		// Deserialize without validation — the reconstructed block will be validated later.
		h := headerFromProtoNoValidate(pp.CompactHeader)
		p.CompactHeader = &h
	}
	if pp.CompactLastCommit != nil {
		c, err := CommitFromProto(pp.CompactLastCommit)
		if err == nil {
			p.CompactLastCommit = c
		}
	}
	p.ProposerAddress = pp.ProposerAddress
	if len(pp.CompactEvidence) > 0 {
		var evProto cmtproto.EvidenceList
		if err := evProto.Unmarshal(pp.CompactEvidence); err == nil {
			var evData EvidenceData
			if err := evData.FromProto(&evProto); err == nil {
				p.CompactEvidence = evData
			}
		}
	}

	return p, p.ValidateBasic()
}
