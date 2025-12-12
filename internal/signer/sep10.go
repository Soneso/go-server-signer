package signer

import (
	"fmt"

	"github.com/stellar/go/keypair"
	"github.com/stellar/go/txnbuild"
	"github.com/stellar/go/xdr"
)

// SignSEP10Transaction signs a SEP-10 transaction envelope
func SignSEP10Transaction(transactionXDR, networkPassphrase, secretKey string) (string, error) {
	// Parse the keypair from secret
	kp, err := keypair.Parse(secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to parse secret key: %w", err)
	}

	fullKP, ok := kp.(*keypair.Full)
	if !ok {
		return "", fmt.Errorf("secret key is not a full keypair")
	}

	// Parse the transaction envelope from XDR
	genericTx, err := txnbuild.TransactionFromXDR(transactionXDR)
	if err != nil {
		return "", fmt.Errorf("failed to parse transaction XDR: %w", err)
	}

	// Get the transaction (not fee bump)
	tx, ok := genericTx.Transaction()
	if !ok {
		return "", fmt.Errorf("expected a regular transaction, not a fee bump transaction")
	}

	// Sign the transaction
	signedTx, err := tx.Sign(networkPassphrase, fullKP)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Convert back to base64 XDR
	signedXDR, err := signedTx.Base64()
	if err != nil {
		return "", fmt.Errorf("failed to encode signed transaction: %w", err)
	}

	return signedXDR, nil
}

// ValidateTransaction performs basic validation on the transaction
func ValidateTransaction(transactionXDR string) error {
	var envelope xdr.TransactionEnvelope
	err := xdr.SafeUnmarshalBase64(transactionXDR, &envelope)
	if err != nil {
		return fmt.Errorf("invalid transaction XDR: %w", err)
	}
	return nil
}
