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

	// Use current time for creation time
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
	gpgKey.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Id,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime:              creationTime,
			SigType:                   packet.SigTypePositiveCert,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      crypto.SHA256,
			IsPrimaryId:               &isPrimaryID,
			FlagsValid:                true,
			FlagSign:                  true,
			FlagCertify:               true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &gpgKey.PrimaryKey.KeyId,
		},
	}

	// Pass a config with the creation time
	config := &packet.Config{
		Time: func() time.Time { return creationTime },
	}

	// Sign the User ID
	err = gpgKey.Identities[uid.Id].SelfSignature.SignUserId(uid.Id, gpgKey.PrimaryKey, gpgKey.PrivateKey, config)
	if err != nil {
		return nil, err
	}

	return gpgKey, nil
}
