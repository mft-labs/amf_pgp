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
	"compress/gzip"
	_ "crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	_ "golang.org/x/crypto/ripemd160"
	"io"
	"os"
)

func DecryptWithArmored2(entity *openpgp.Entity, encrypted *os.File) (io.Reader, error) {
	// Decode message
	block, err := armor.Decode(encrypted)
	if err != nil {
		return nil, fmt.Errorf("Error decoding: %v", err)
	}
	if block.Type != "Message"  && block.Type != "PGP MESSAGE" {
		return nil, errors.New("Invalid message type")
	}

	// Decrypt message
	entityList := openpgp.EntityList{entity}
	messageReader, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Error reading message: %v", err)
	}
	/*read, err := ioutil.ReadAll(messageReader.UnverifiedBody)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading unverified body: %v", err)
	}

	return read, nil*/
	return messageReader.UnverifiedBody, nil
}

func Decrypt2(entity *openpgp.Entity, encrypted *os.File) (io.Reader, error) {
	// Decrypt message
	entityList := openpgp.EntityList{entity}
	messageReader, err := openpgp.ReadMessage(encrypted, entityList, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Error reading message: %v", err)
	}
	return messageReader.UnverifiedBody, nil
}

func DecryptWithArmoredAndGzip2(entity *openpgp.Entity, encrypted *os.File) (io.Reader, error) {
	// Decode message
	block, err := armor.Decode(encrypted)
	if err != nil {
		return nil, fmt.Errorf("Error decoding: %v", err)
	}
	if block.Type != "Message"  && block.Type != "PGP MESSAGE" {
		return nil, errors.New("Invalid message type")
	}

	// Decrypt message
	entityList := openpgp.EntityList{entity}
	messageReader, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Error reading message: %v", err)
	}
		uncompressed, err := gzip.NewReader(messageReader.UnverifiedBody)
		if err != nil {
			return nil, fmt.Errorf("Error initializing gzip reader: %v", err)
		}
		//defer uncompressed.Close()

		return uncompressed, nil

}

func DecryptWithGzip2(entity *openpgp.Entity, encrypted *os.File) (io.Reader, error) {
	entityList := openpgp.EntityList{entity}
	messageReader, err := openpgp.ReadMessage(encrypted, entityList, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Error reading message: %v", err)
	}
	uncompressed, err := gzip.NewReader(messageReader.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("Error initializing gzip reader: %v", err)
	}
	return uncompressed, nil
}


func DecryptWithArmoredAndPassphrase2(entity *openpgp.Entity, encrypted *os.File, passphraseByte []byte) (io.Reader, error) {
	block, err := armor.Decode(encrypted)
	if err != nil {
		return nil, fmt.Errorf("Error decoding: %v", err)
	}
	if block.Type != "Message" && block.Type != "PGP MESSAGE"{
		return nil, errors.New("Invalid message type")
	}

	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	// Decrypt message
	entityList := openpgp.EntityList{entity}
	messageReader, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Error reading message: %v", err)
	}


	return messageReader.UnverifiedBody, nil
}

func DecryptWithPassphrase2(entity *openpgp.Entity, encrypted *os.File, passphraseByte []byte) (io.Reader, error) {
	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	// Decrypt message
	entityList := openpgp.EntityList{entity}
	messageReader, err := openpgp.ReadMessage(encrypted, entityList, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Error reading message: %v", err)
	}
	return messageReader.UnverifiedBody, nil
}

func DecryptWithArmoredAndPassphraseAndGzip2(entity *openpgp.Entity, encrypted *os.File, passphraseByte []byte) (io.Reader, error) {
	// Decode message
	block, err := armor.Decode(encrypted)
	if err != nil {
		return nil, fmt.Errorf("Error decoding: %v", err)
	}
	if block.Type != "Message"  && block.Type != "PGP MESSAGE" {
		return nil, errors.New("Invalid message type")
	}

	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	entityList := openpgp.EntityList{entity}
	messageReader, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Error reading message: %v", err)
	}
	uncompressed, err := gzip.NewReader(messageReader.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("Error initializing gzip reader: %v", err)
	}

	return uncompressed, nil
}

func DecryptWithPassphraseAndGzip2(entity *openpgp.Entity, encrypted *os.File, passphraseByte []byte) (io.Reader, error) {
	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	// Decrypt message
	entityList := openpgp.EntityList{entity}
	messageReader, err := openpgp.ReadMessage(encrypted, entityList, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Error reading message: %v", err)
	}

	uncompressed, err := gzip.NewReader(messageReader.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("Error initializing gzip reader: %v", err)
	}
	return uncompressed, nil
}
