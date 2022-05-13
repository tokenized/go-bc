package spv

import (
	"context"
	"fmt"

	"github.com/tokenized/go-bc"
	"github.com/tokenized/go-bt"
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/bsor"
	"github.com/tokenized/pkg/json_envelope"

	"github.com/pkg/errors"
)

// TxStore interfaces the a tx store.
type TxStore interface {
	Tx(ctx context.Context, txID bitcoin.Hash32) (*bt.Tx, error)
}

// MerkleProofStore interfaces a Merkle Proof store.
type MerkleProofStore interface {
	MerkleProof(ctx context.Context, txID bitcoin.Hash32) (*bc.MerkleProof, error)
}

// Ancestry is a struct which contains all information needed for a transaction to be verified.
// this contains all ancestors for the transaction allowing proofs etc to be verified.
//
// NOTE: this is the JSON format of the Ancestry but in a nested format (in comparison) with
// the flat structure that the TSC uses. This allows verification to become a lot easier and
// use a recursive function.
type Ancestor struct {
	Tx            *bt.Tx                       `bsor:"1" json:"tx,omitempty"`
	Proof         *bc.MerkleProof              `bsor:"2" json:"proof,omitempty"`
	MapiResponses []json_envelope.JSONEnvelope `bsor:"3" json:"mapiResponses,omitempty"`
}

type Ancestors []*Ancestor

// IsAnchored returns true if the ancestry has a merkle proof.
func (e *Ancestor) IsAnchored() bool {
	return e.Proof != nil
}

// Ancestor will return a ancestor if found otherwise a ErrNotAllInputsSupplied error is returned.
func (e Ancestors) Ancestor(txID bitcoin.Hash32) (*Ancestor, error) {
	for _, ancestor := range e {
		if ancestor.Tx.TxHash().Equal(&txID) {
			return ancestor, nil
		}
	}

	return nil, errors.Wrapf(ErrNotAllInputsSupplied, "expected parent tx %s is missing", txID)
}

// Populate populates the ancestors for a provided tx's inputs.
func (a *Ancestors) Populate(ctx context.Context, txStore TxStore, mpStore MerkleProofStore,
	tx *bt.Tx) error {

	for _, input := range tx.Inputs {
		pTxID := bt.ReverseBytes(input.PreviousTxID())
		txid, _ := bitcoin.NewHash32(pTxID)

		_, err := a.Ancestor(*txid)
		if err == nil {
			continue // already have this tx
		}

		if errors.Cause(err) != ErrNotAllInputsSupplied {
			return errors.Wrap(err, "ancestor")
		}

		// Build a *bt.Tx from its TxID and recursively call this function building
		// for inputs without proofs, until a parent with a Merkle Proof is found.
		pTx, err := txStore.Tx(ctx, *txid)
		if err != nil {
			return errors.Wrapf(err, "failed to get tx %s", txid)
		}
		if pTx == nil {
			return fmt.Errorf("could not find tx %s", txid)
		}

		// Check the store for a Merkle Proof for the current input.
		mp, err := mpStore.MerkleProof(ctx, *txid)
		if err != nil {
			return errors.Wrapf(err, "failed to get merkle proof for tx %s", txid)
		}
		// If a Merkle Proof is found, create the ancestry and skip any further recursion
		if mp != nil {
			*a = append(*a, &Ancestor{
				Tx:    pTx,
				Proof: mp,
			})

			continue
		}

		if err := a.Populate(ctx, txStore, mpStore, pTx); err != nil {
			return errors.Wrap(err, pTx.TxHash().String())
		}
	}

	return nil
}

func (e Ancestors) Bytes() ([]byte, error) {
	b, err := bsor.MarshalBinary(e)
	if err != nil {
		return nil, errors.Wrap(err, "marshal")
	}

	return append([]byte{1}, b...), nil // add version
}

func (e *Ancestors) ParseBytes(b []byte) error {
	if b[0] != 1 { // the first byte is the version number.
		return ErrUnsupporredVersion
	}

	if _, err := bsor.UnmarshalBinary(b[1:], e); err != nil {
		return errors.Wrap(err, "unmarshal")
	}

	return nil
}
