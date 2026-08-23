package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
)

// cmdSecrets generates the secrets a deployment needs.
//
// It exists so that "generate a 32-byte base64 secret" is not left as an
// exercise involving openssl flags nobody remembers, and so the operator is
// told what each one does and what happens if they lose it — which is the
// part that actually matters and the part a README paragraph gets skipped
// over.
func cmdSecrets(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("secrets", flag.ExitOnError)
	which := fs.String("for", "all", "tenant-salt, audit-checkpoint, or all")
	if err := fs.Parse(args); err != nil {
		return err
	}

	generate := func() (string, error) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(b), nil
	}

	if *which == "all" || *which == "tenant-salt" {
		v, err := generate()
		if err != nil {
			return err
		}
		fmt.Printf("STATUSHUB_TENANT_SALT_MASTER=%s\n", v)
		fmt.Println(`
  Every tenant's pseudonymisation salt is derived from this, so customer
  identifiers can be hashed rather than stored in the clear.

  Losing it does not expose anything — the hashes stay irreversible — but
  replacing it re-derives every salt, which orphans every hash already
  stored. Existing events keep their old hashes and new ones get different
  values for the same person, so correlation breaks and an erasure request
  matches only half a subject's events. Treat rotation as a migration, not a
  routine act.`)
	}

	if *which == "all" || *which == "audit-checkpoint" {
		v, err := generate()
		if err != nil {
			return err
		}
		fmt.Printf("\nSTATUSHUB_AUDIT_CHECKPOINT_SEED=%s\n", v)
		fmt.Println(`
  The ed25519 seed the nightly audit checkpoints are signed with.

  Keep it outside the database. That is the entire point: an attacker who
  alters an audit record must also forge every checkpoint published since,
  which needs this key — so a full database compromise does not include it.
  The matching public key is published, and a customer's auditor verifies
  against that without involving you.`)
	}

	fmt.Println("\nStore these in your secret manager. They are not recoverable.")
	return nil
}
