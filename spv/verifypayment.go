package spv

import (
	"context"

	"golang.org/x/sync/errgroup"

	"github.com/libsv/go-bt/v2"
	"github.com/libsv/go-bt/v2/bscript/interpreter"
	"github.com/pkg/errors"
)

// VerifyPayment verifies whether or not the txs supplied via the supplied spv.Envelope are valid
func (v *verifier) VerifyPayment(ctx context.Context, initialPayment *Envelope) (bool, error) {
	if initialPayment == nil {
		return false, ErrNilInitialPayment
	}

	// The tip tx is the transaction we're trying to verify, and it should not have a supplied
	// Merkle Proof.
	if initialPayment.IsAnchored() {
		return false, ErrTipTxConfirmed
	}

	valid, err := v.verifyTxs(ctx, initialPayment)
	if err != nil {
		return false, err
	}

	return valid, nil
}

func (v *verifier) verifyTxs(ctx context.Context, payment *Envelope) (bool, error) {
	tx, err := bt.NewTxFromString(payment.RawTx)
	if err != nil {
		return false, err
	}

	// If at the beginning or middle of the tx chain and tx is unconfirmed, fail and error.
	if !payment.IsAnchored() && (payment.Parents == nil || len(payment.Parents) == 0) {
		return false, errors.Wrapf(ErrNoConfirmedTransaction, "tx %s has no confirmed/anchored tx", tx.TxID())
	}

	// Recurse back to the anchor transactions of the transaction chain and verify forward towards
	// the tip transaction. This way, we check that the first transactions in the chain are anchored
	// to the blockchain through a valid Merkle Proof.
	for parentTxID, parent := range payment.Parents {
		if parent.TxID == "" {
			parent.TxID = parentTxID
		}

		valid, err := v.verifyTxs(ctx, parent)
		if err != nil {
			return false, err
		}
		if !valid {
			return false, nil
		}
	}

	// If a Merkle Proof is provided, assume we are at the anchor/beginning of the tx chain.
	// Verify and return the result.
	if payment.IsAnchored() {
		return v.verifyTxAnchor(ctx, payment)
	}

	// We must verify the tx or else we can not know if any of it's child txs are valid.
	return v.verifyUnconfirmedTx(ctx, tx, payment)
}

func (v *verifier) verifyTxAnchor(ctx context.Context, payment *Envelope) (bool, error) {
	proofTxID := payment.Proof.TxOrID
	if len(proofTxID) != 64 {
		proofTx, err := bt.NewTxFromString(payment.Proof.TxOrID)
		if err != nil {
			return false, err
		}

		proofTxID = proofTx.TxID()
	}

	// If the txid of the Merkle Proof doesn't match the txid provided in the spv.Envelope,
	// fail and error
	if proofTxID != payment.TxID {
		return false, errors.Wrapf(ErrTxIDMismatch, "tx id %s does not match proof tx id %s", payment.TxID, proofTxID)
	}

	valid, _, err := v.VerifyMerkleProofJSON(ctx, payment.Proof)
	if err != nil {
		return false, err
	}

	return valid, nil
}

func (v *verifier) verifyUnconfirmedTx(ctx context.Context, tx *bt.Tx, payment *Envelope) (bool, error) {
	// If no tx inputs have been provided, fail and error
	if len(tx.Inputs) == 0 {
		return false, errors.Wrapf(ErrNoTxInputsToVerify, "tx %s has no inputs to verify", tx.TxID())
	}

	// perform the script validations in parallel
	errs, _ := errgroup.WithContext(ctx)
	for i := range tx.Inputs {
		idx := i // copy current value of i for concurrent use
		errs.Go(func() error {
			input := tx.InputIdx(idx)

			parent, ok := payment.Parents[input.PreviousTxIDStr()]
			if !ok {
				return errors.Wrapf(ErrNotAllInputsSupplied, "tx %s is missing input %d in its parents' envelope", tx.TxID(), idx)
			}

			parentTx, err := bt.NewTxFromString(parent.RawTx)
			if err != nil {
				return err
			}

			output := parentTx.OutputIdx(int(input.PreviousTxOutIndex))
			// If the input is indexing an output that is out of bounds, fail and error
			if output == nil {
				return errors.Wrapf(ErrInputRefsOutOfBoundsOutput, "tx %s input %d is referencing an out of bounds output", tx.TxID(), idx)
			}

			err = v.eng.Execute(interpreter.ExecutionParams{
				PreviousTxOut: output,
				InputIdx:      idx,
				Tx:            tx,
				Flags:         interpreter.ScriptEnableSighashForkID | interpreter.ScriptUTXOAfterGenesis,
			})

			if err != nil {
				return errors.Wrap(ErrScriptValidationFailed, err.Error())
			}

			return nil
		})
	}

	if err := errs.Wait(); err != nil {
		return false, err
	}

	return true, nil
}
