package signer

import (
	"testing"

	"github.com/stellar/go/keypair"
	"github.com/stellar/go/network"
	"github.com/stellar/go/txnbuild"
)

func TestSignSEP10Transaction(t *testing.T) {
	// Create a test keypair
	kp, err := keypair.Random()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	// Create a simple transaction
	sourceAccount := txnbuild.NewSimpleAccount(kp.Address(), 0)

	tx, err := txnbuild.NewTransaction(
		txnbuild.TransactionParams{
			SourceAccount:        &sourceAccount,
			IncrementSequenceNum: true,
			Operations: []txnbuild.Operation{
				&txnbuild.ManageData{
					Name:  "test",
					Value: []byte("test data"),
				},
			},
			BaseFee:       txnbuild.MinBaseFee,
			Preconditions: txnbuild.Preconditions{TimeBounds: txnbuild.NewTimeout(300)},
		},
	)
	if err != nil {
		t.Fatalf("failed to build transaction: %v", err)
	}

	// Convert to base64 XDR
	txXDR, err := tx.Base64()
	if err != nil {
		t.Fatalf("failed to encode transaction: %v", err)
	}

	// Sign the transaction
	networkPassphrase := network.TestNetworkPassphrase
	signedXDR, err := SignSEP10Transaction(txXDR, networkPassphrase, kp.Seed())
	if err != nil {
		t.Fatalf("SignSEP10Transaction failed: %v", err)
	}

	// Verify the signed transaction
	signedTx, err := txnbuild.TransactionFromXDR(signedXDR)
	if err != nil {
		t.Fatalf("failed to parse signed transaction: %v", err)
	}

	simpleTx, ok := signedTx.Transaction()
	if !ok {
		t.Fatal("expected a simple transaction")
	}

	// Verify that we have at least one signature
	if len(simpleTx.Signatures()) == 0 {
		t.Fatal("expected at least one signature")
	}

	// Verify the signature is valid
	txHash, err := simpleTx.Hash(networkPassphrase)
	if err != nil {
		t.Fatalf("failed to get transaction hash: %v", err)
	}

	err = kp.Verify(txHash[:], simpleTx.Signatures()[0].Signature)
	if err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func TestSignSEP10Transaction_InvalidXDR(t *testing.T) {
	kp, err := keypair.Random()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	_, err = SignSEP10Transaction("invalid-xdr", network.TestNetworkPassphrase, kp.Seed())
	if err == nil {
		t.Fatal("expected error for invalid XDR")
	}
}

func TestSignSEP10Transaction_InvalidSecret(t *testing.T) {
	kp, err := keypair.Random()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	sourceAccount := txnbuild.NewSimpleAccount(kp.Address(), 0)
	tx, err := txnbuild.NewTransaction(
		txnbuild.TransactionParams{
			SourceAccount:        &sourceAccount,
			IncrementSequenceNum: true,
			Operations: []txnbuild.Operation{
				&txnbuild.ManageData{
					Name:  "test",
					Value: []byte("test data"),
				},
			},
			BaseFee:       txnbuild.MinBaseFee,
			Preconditions: txnbuild.Preconditions{TimeBounds: txnbuild.NewTimeout(300)},
		},
	)
	if err != nil {
		t.Fatalf("failed to build transaction: %v", err)
	}

	txXDR, err := tx.Base64()
	if err != nil {
		t.Fatalf("failed to encode transaction: %v", err)
	}

	_, err = SignSEP10Transaction(txXDR, network.TestNetworkPassphrase, "invalid-secret")
	if err == nil {
		t.Fatal("expected error for invalid secret")
	}
}

func TestValidateTransaction(t *testing.T) {
	kp, err := keypair.Random()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	sourceAccount := txnbuild.NewSimpleAccount(kp.Address(), 0)
	tx, err := txnbuild.NewTransaction(
		txnbuild.TransactionParams{
			SourceAccount:        &sourceAccount,
			IncrementSequenceNum: true,
			Operations: []txnbuild.Operation{
				&txnbuild.ManageData{
					Name:  "test",
					Value: []byte("test data"),
				},
			},
			BaseFee:       txnbuild.MinBaseFee,
			Preconditions: txnbuild.Preconditions{TimeBounds: txnbuild.NewTimeout(300)},
		},
	)
	if err != nil {
		t.Fatalf("failed to build transaction: %v", err)
	}

	txXDR, err := tx.Base64()
	if err != nil {
		t.Fatalf("failed to encode transaction: %v", err)
	}

	err = ValidateTransaction(txXDR)
	if err != nil {
		t.Fatalf("ValidateTransaction failed: %v", err)
	}
}

func TestValidateTransaction_Invalid(t *testing.T) {
	err := ValidateTransaction("invalid-xdr")
	if err == nil {
		t.Fatal("expected error for invalid XDR")
	}
}
