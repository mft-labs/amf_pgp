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
	"bytes"
	"compress/gzip"
	_ "crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	_ "golang.org/x/crypto/ripemd160"
	"io/ioutil"
)

func DecryptWithArmored(entity *openpgp.Entity, encrypted []byte) ([]byte, error) {
	// Decode message
	block, err := armor.Decode(bytes.NewReader(encrypted))
	if err != nil {
		return []byte{}, fmt.Errorf("Error decoding: %v", err)
	}
	if block.Type != "Message"  && block.Type != "PGP MESSAGE" {
		return []byte{}, errors.New("Invalid message type")
	}

	// Decrypt message
	entityList := openpgp.EntityList{entity}
	messageReader, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading message: %v", err)
	}
	read, err := ioutil.ReadAll(messageReader.UnverifiedBody)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading unverified body: %v", err)
	}

	return read, nil
}

func Decrypt(entity *openpgp.Entity, encrypted []byte) ([]byte, error) {
	// Decrypt message
	entityList := openpgp.EntityList{entity}
	messageReader, err := openpgp.ReadMessage(bytes.NewReader(encrypted), entityList, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading message: %v", err)
	}
	read, err := ioutil.ReadAll(messageReader.UnverifiedBody)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading unverified body: %v", err)
	}

	return read, nil
}

func DecryptWithArmoredAndGzip(entity *openpgp.Entity, encrypted []byte) ([]byte, error) {
	// Decode message
	block, err := armor.Decode(bytes.NewReader(encrypted))
	if err != nil {
		return []byte{}, fmt.Errorf("Error decoding: %v", err)
	}
	if block.Type != "Message"  && block.Type != "PGP MESSAGE" {
		return []byte{}, errors.New("Invalid message type")
	}

	// Decrypt message
	entityList := openpgp.EntityList{entity}
	messageReader, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading message: %v", err)
	}
	read, err := ioutil.ReadAll(messageReader.UnverifiedBody)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading unverified body: %v", err)
	}

	// Uncompress message
	//TODO: removed uncompress

		reader := bytes.NewReader(read)
		uncompressed, err := gzip.NewReader(reader)
		if err != nil {
			return []byte{}, fmt.Errorf("Error initializing gzip reader: %v", err)
		}
		defer uncompressed.Close()

		out, err := ioutil.ReadAll(uncompressed)
		if err != nil {
			return []byte{}, err
		}

		// Return output - an unencoded, unencrypted, and uncompressed message
		return out, nil

}

func DecryptWithGzip(entity *openpgp.Entity, encrypted []byte) ([]byte, error) {
	// Decrypt message
	entityList := openpgp.EntityList{entity}
	messageReader, err := openpgp.ReadMessage(bytes.NewReader(encrypted), entityList, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading message: %v", err)
	}
	read, err := ioutil.ReadAll(messageReader.UnverifiedBody)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading unverified body: %v", err)
	}

	// Uncompress message
	//TODO: removed uncompress

	reader := bytes.NewReader(read)
	uncompressed, err := gzip.NewReader(reader)
	if err != nil {
		return []byte{}, fmt.Errorf("Error initializing gzip reader: %v", err)
	}
	defer uncompressed.Close()

	out, err := ioutil.ReadAll(uncompressed)
	if err != nil {
		return []byte{}, err
	}

	// Return output - an unencoded, unencrypted, and uncompressed message
	return out, nil

}


func DecryptWithArmoredAndPassphrase(entity *openpgp.Entity, encrypted []byte, passphraseByte []byte) ([]byte, error) {
	// Decode message
	block, err := armor.Decode(bytes.NewReader(encrypted))
	if err != nil {
		return []byte{}, fmt.Errorf("Error decoding: %v", err)
	}
	if block.Type != "Message" && block.Type != "PGP MESSAGE"{
		return []byte{}, errors.New("Invalid message type")
	}

	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	// Decrypt message
	entityList := openpgp.EntityList{entity}
	messageReader, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading message: %v", err)
	}
	read, err := ioutil.ReadAll(messageReader.UnverifiedBody)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading unverified body: %v", err)
	}

	return read, nil
}

func DecryptWithPassphrase(entity *openpgp.Entity, encrypted []byte, passphraseByte []byte) ([]byte, error) {
	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	// Decrypt message
	entityList := openpgp.EntityList{entity}
	messageReader, err := openpgp.ReadMessage(bytes.NewReader(encrypted), entityList, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading message: %v", err)
	}
	read, err := ioutil.ReadAll(messageReader.UnverifiedBody)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading unverified body: %v", err)
	}

	return read, nil
}

func DecryptWithArmoredAndPassphraseAndGzip(entity *openpgp.Entity, encrypted []byte, passphraseByte []byte) ([]byte, error) {
	// Decode message
	block, err := armor.Decode(bytes.NewReader(encrypted))
	if err != nil {
		return []byte{}, fmt.Errorf("Error decoding: %v", err)
	}
	if block.Type != "Message"  && block.Type != "PGP MESSAGE" {
		return []byte{}, errors.New("Invalid message type")
	}

	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	// Decrypt message
	entityList := openpgp.EntityList{entity}
	messageReader, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading message: %v", err)
	}
	read, err := ioutil.ReadAll(messageReader.UnverifiedBody)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading unverified body: %v", err)
	}

	// Uncompress message
	//TODO: removed uncompress

		reader := bytes.NewReader(read)
		uncompressed, err := gzip.NewReader(reader)
		if err != nil {
			return []byte{}, fmt.Errorf("Error initializing gzip reader: %v", err)
		}
		defer uncompressed.Close()

		out, err := ioutil.ReadAll(uncompressed)
		if err != nil {
			return []byte{}, err
		}

		// Return output - an unencoded, unencrypted, and uncompressed message
		return out, nil
}

func DecryptWithPassphraseAndGzip(entity *openpgp.Entity, encrypted []byte, passphraseByte []byte) ([]byte, error) {
	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	// Decrypt message
	entityList := openpgp.EntityList{entity}
	messageReader, err := openpgp.ReadMessage(bytes.NewReader(encrypted), entityList, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading message: %v", err)
	}
	read, err := ioutil.ReadAll(messageReader.UnverifiedBody)
	if err != nil {
		return []byte{}, fmt.Errorf("Error reading unverified body: %v", err)
	}

	// Uncompress message
	//TODO: removed uncompress

	reader := bytes.NewReader(read)
	uncompressed, err := gzip.NewReader(reader)
	if err != nil {
		return []byte{}, fmt.Errorf("Error initializing gzip reader: %v", err)
	}
	defer uncompressed.Close()

	out, err := ioutil.ReadAll(uncompressed)
	if err != nil {
		return []byte{}, err
	}

	// Return output - an unencoded, unencrypted, and uncompressed message
	return out, nil
}
