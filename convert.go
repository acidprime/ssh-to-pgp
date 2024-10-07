package main

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"reflect"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"golang.org/x/crypto/ssh"
)

const (
	// Hash Algorithm Numbers (as per RFC 4880)
	HashSHA256 = 8
	HashSHA384 = 9
	HashSHA512 = 10
	HashSHA224 = 11

	// Symmetric Key Algorithm Numbers
	CipherAES128 = 7
	CipherAES192 = 8
	CipherAES256 = 9

	// Compression Algorithm Numbers
	CompressionNone = 0
	CompressionZIP  = 1
	CompressionZLIB = 2
)

func parsePrivateKey(sshPrivateKey []byte) (*rsa.PrivateKey, error) {
	privateKey, err := ssh.ParseRawPrivateKey(sshPrivateKey)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := privateKey.(*rsa.PrivateKey)

	if !ok {
		return nil, fmt.Errorf("Only RSA keys are supported right now, got: %s", reflect.TypeOf(privateKey))
	}

	return rsaKey, nil
}

func SSHPrivateKeyToPGP(sshPrivateKey []byte, name string, comment string, email string) (*openpgp.Entity, error) {
	key, err := parsePrivateKey(sshPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private ssh key: %w", err)
	}

	creationTime := time.Now()

	gpgKey := &openpgp.Entity{
		PrimaryKey: packet.NewRSAPublicKey(creationTime, &key.PublicKey),
		PrivateKey: packet.NewRSAPrivateKey(creationTime, key),
		Identities: make(map[string]*openpgp.Identity),
	}
	uid := packet.NewUserId(name, comment, email)
	if uid == nil {
		return nil, fmt.Errorf("error creating User ID")
	}

	isPrimaryID := true
	sig := &packet.Signature{
		Version:                   4,
		CreationTime:              creationTime,
		SigType:                   packet.SigTypePositiveCert,
		PubKeyAlgo:                packet.PubKeyAlgoRSA,
		Hash:                      crypto.SHA256,
		IssuerKeyId:               &gpgKey.PrimaryKey.KeyId,
		IssuerFingerprint:         gpgKey.PrimaryKey.Fingerprint,
		IsPrimaryId:               &isPrimaryID,
		FlagsValid:                true,
		FlagSign:                  true,
		FlagCertify:               true,
		FlagEncryptCommunications: true,
		FlagEncryptStorage:        true,
		PreferredSymmetric: []uint8{
			CipherAES256,
			CipherAES192,
			CipherAES128,
		},
		PreferredHash: []uint8{
			HashSHA256,
			HashSHA384,
			HashSHA512,
			HashSHA224,
		},
		PreferredCompression: []uint8{
			CompressionZLIB,
			CompressionZIP,
			CompressionNone,
		},
		// Remove the Features field if it's not defined
		// Features: []uint8{1}, // Modification detection
	}

	gpgKey.Identities[uid.Id] = &openpgp.Identity{
		Name:          uid.Id,
		UserId:        uid,
		SelfSignature: sig,
	}

	config := &packet.Config{
		DefaultHash: crypto.SHA256,
		Time:        func() time.Time { return creationTime },
	}

	// Sign the User ID
	err = sig.SignUserId(uid.Id, gpgKey.PrimaryKey, gpgKey.PrivateKey, config)
	if err != nil {
		return nil, fmt.Errorf("error signing user ID: %w", err)
	}

	return gpgKey, nil
}
