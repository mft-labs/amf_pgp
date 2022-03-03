/****************************************************************************
 *
 * Copyright (C) Agile Data, Inc - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by MFTLABS <code@mftlabs.io>
 *
 ****************************************************************************/

package pgp

import (
	amf "github.com/mft-labs/amfcore"
	"crypto"
	"errors"
	"fmt"

	//"fmt"
	"io"

	"github.com/alecthomas/log4go"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"

	//"log"
	"io/ioutil"
	"encoding/base64"
	"os"
	"strings"
)

type PGP struct {
	publicKey  string
	privateKey string
	infile     string
	outfile    string
	sign       bool
	verify     bool
	enc        bool
	log        log4go.Logger
}

func (pgp *PGP) Init(publicKey, privateKey, infile, outfile string, sign, verify, enc bool, log log4go.Logger) {
	pgp.publicKey = publicKey
	pgp.privateKey = privateKey
	pgp.infile = infile
	pgp.outfile = outfile
	pgp.sign = sign
	pgp.verify = verify
	pgp.enc = enc
	pgp.log = log
	pgp.ShowParams()
}

func (pgp *PGP) ShowParams() {
	pgp.log.Debug(fmt.Sprintf("\nPublicKey = %s, PrivateKey = %s, Infile = %s, Outfile = %s, Sign = %v, verify = %v, encrypt = %v",
		pgp.publicKey, pgp.privateKey, pgp.infile, pgp.outfile, pgp.sign, pgp.verify, pgp.enc))
}

func (pgp *PGP) EncryptDocument() error {
	pgp.log.Debug(fmt.Sprintf("\nArrived to encrypt document with %s, %s, %s, %s", pgp.publicKey, pgp.privateKey, pgp.infile, pgp.outfile))
	recipient, err := pgp.ReadEntity(pgp.publicKey)
	if err != nil {
		//pgp.log.Println(err)
		return err
	}

	signer, err := pgp.ReadEntity(pgp.privateKey)
	if err != nil {
		//pgp.log.Println(err)
		return err
	}
	pgp.log.Debug(fmt.Sprintf("\nGoing to read file"))
	src, err := os.Open(pgp.infile)
	if err != nil {
		//pgp.log.Println(err)
		return err
	}
	defer src.Close()

	pgp.log.Debug(fmt.Sprintf("\nGoing to open file for write"))
	dst, err := os.Create(pgp.outfile)
	if err != nil {
		//pgp.log.Println(err)
		return err
	}
	defer dst.Close()
	if pgp.sign {
		pgp.log.Debug(fmt.Sprintf("\nGoing to encrypt the document with sign"))
		return pgp.Encrypt([]*openpgp.Entity{recipient}, signer, src, dst)
	} else {
		pgp.log.Debug(fmt.Sprintf("\nGoing to encrypt the document without sign"))
		return pgp.Encrypt([]*openpgp.Entity{recipient}, nil, src, dst)
	}
}

func (pgp *PGP) DecryptDocument() ([]byte, error) {

	var entityList openpgp.EntityList
	var secretKeyRing = pgp.privateKey

	keyringFileBuffer, err := os.Open(secretKeyRing)
	if err != nil {
		pgp.log.Debug(fmt.Sprintf("\nError occurred:%v --(1)", err))
		return nil, err
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadArmoredKeyRing(keyringFileBuffer)
	if err != nil {
		pgp.log.Debug(fmt.Sprintf("\nError occurred:%v --(2)", err))
		return nil, err
	}

	in, err := os.Open(pgp.infile)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(in, entityList, nil, nil)
	if err != nil {
		pgp.log.Debug(fmt.Sprintf("\nError occurred:%v --(4)", err))
		return nil, err
	}
	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		pgp.log.Debug(fmt.Sprintf("\nError occurred:%v --(5)", err))
		return nil, err
	}
	return bytes, nil
}

func (pgp *PGP) Encrypt(recip []*openpgp.Entity, signer *openpgp.Entity, r io.Reader, w io.Writer) error {
	wc, err := openpgp.Encrypt(w, recip, signer, &openpgp.FileHints{IsBinary: true}, nil)
	if err != nil {
		return err
	}
	if _, err := io.Copy(wc, r); err != nil {
		return err
	}
	return wc.Close()
}

func (pgp *PGP) ReadEntity(name string) (*openpgp.Entity, error) {
	data, err := ioutil.ReadFile(name)
	if err == nil {
		contents := string(data)
		if strings.Contains(contents,";base64,") {
			contents2 := strings.Split(contents,";base64,")
			data, err := base64.StdEncoding.DecodeString(contents2[1])
			if err != nil {
				pgp.log.Debug("\nError occurred while processing document:%v,component name is %v",err,name)
				if strings.Contains(err.Error(),"illegal base64 data at ") {

				} else {
					return nil, fmt.Errorf("Failed to decode base64 entity for PGP")
				}

			}
			amf.WriteFile(name, data)
		}
	} else {
		return nil, fmt.Errorf("Failed to read entity for PGP")
	}

	pgp.log.Debug(fmt.Sprintf("\nReading entity %s", name))
	f, err := os.Open(name)
	if err != nil {
		pgp.log.Debug("Failed to open file for ARMOR %v",err)
		return nil, err
	}
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		pgp.log.Debug("Failed to decode file with ARMOR %v",err)
		return nil, err
	}
	pgp.log.Debug(fmt.Sprintf("\nReading entity with openpgp"))
	return openpgp.ReadEntity(packet.NewReader(block.Body))
}

func (pgp *PGP) DecodePrivateKey(filename string) (*packet.PrivateKey, error) {

	// open ascii armored private key
	in, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	block, err := armor.Decode(in)
	if err != nil {
		return nil, err
	}

	if block.Type != openpgp.PrivateKeyType {
		return nil, errors.New("Invalid private key file")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		return nil, err
	}

	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		return nil, errors.New("Invalid private key")
	}
	return key, nil
}

func (pgp *PGP) DecodePublicKey(filename string) (*packet.PublicKey, error) {

	// open ascii armored public key
	in, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	block, err := armor.Decode(in)
	if err != nil {
		return nil, err
	}

	if block.Type != openpgp.PublicKeyType {
		return nil, errors.New("Invalid private key file")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		return nil, err
	}

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		return nil, errors.New("Invalid public key")
	}
	return key, nil
}

func (pgp *PGP) CreateEntityFromKeys(pubKey *packet.PublicKey, privKey *packet.PrivateKey) *openpgp.Entity {
	config := packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: 4096,
	}
	currentTime := config.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := false

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	keyLifetimeSecs := uint32(86400 * 365)

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			PreferredHash:             []uint8{8}, // SHA-256
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifetimeSecs,
		},
	}
	return &e
}

func (pgp *PGP) ReadFile(filename string) []byte {
	dat, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil
	}
	return dat
}
func (pgp *PGP) WriteFile(filename string, contents []byte) error {
	err := ioutil.WriteFile(filename, contents, 0644)
	return err
}
