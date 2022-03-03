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
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	_ "golang.org/x/crypto/ripemd160"
	//"bufio"
	"io"
)

func Encrypt(entity *openpgp.Entity, message []byte) ([]byte, error) {
	// Create buffer to write output to
	buf := new(bytes.Buffer)

	// Create encryptor with encoder
	encryptorWriter, err := openpgp.Encrypt(buf, []*openpgp.Entity{entity}, nil, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error creating entity for encryption: %v", err)
	}

	messageReader := bytes.NewReader(message)
	_, err = io.Copy(encryptorWriter, messageReader)
	if err != nil {
		return []byte{}, fmt.Errorf("Error writing data to compressor: %v", err)
	}
	encryptorWriter.Close()

	// Return buffer output - an encoded, encrypted, and compressed message
	return buf.Bytes(), nil
}

func EncryptWithArmored(entity *openpgp.Entity, message []byte) ([]byte, error) {
	// Create buffer to write output to
	buf := new(bytes.Buffer)

	// Create encoder
	encoderWriter, err := armor.Encode(buf, "PGP MESSAGE", make(map[string]string))
	if err != nil {
		return []byte{}, fmt.Errorf("Error creating OpenPGP armor: %v", err)
	}

	// Create encryptor with encoder
	encryptorWriter, err := openpgp.Encrypt(encoderWriter, []*openpgp.Entity{entity}, nil, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error creating entity for encryption: %v", err)
	}

	messageReader := bytes.NewReader(message)
	_, err = io.Copy(encryptorWriter, messageReader)
	if err != nil {
		return []byte{}, fmt.Errorf("Error writing data to compressor: %v", err)
	}
	encryptorWriter.Close()
	encoderWriter.Close()

	// Return buffer output - an encoded, encrypted, and compressed message
	return buf.Bytes(), nil
}

func EncryptWithGZip(entity *openpgp.Entity, message []byte) ([]byte, error) {
	// Create buffer to write output to
	buf := new(bytes.Buffer)

	// Create encryptor with encoder
	encryptorWriter, err := openpgp.Encrypt(buf, []*openpgp.Entity{entity}, nil, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error creating entity for encryption: %v", err)
	}

	// Create compressor with encryptor

	//TODO: Removed packing with GZIP
	compressorWriter, err := gzip.NewWriterLevel(encryptorWriter, gzip.BestCompression)
	if err != nil {
		return []byte{}, fmt.Errorf("Invalid compression level: %v", err)
	}

	// Write message to compressor
	messageReader := bytes.NewReader(message)
	_, err = io.Copy(compressorWriter, messageReader)
	if err != nil {
		return []byte{}, fmt.Errorf("Error writing data to compressor: %v", err)
	}

	compressorWriter.Close()
	encryptorWriter.Close()

	// Return buffer output - an encoded, encrypted, and compressed message
	return buf.Bytes(), nil
}

func EncryptWithArmoredAndGZip(entity *openpgp.Entity, message []byte) ([]byte, error) {
	// Create buffer to write output to
	buf := new(bytes.Buffer)

	// Create encoder
	encoderWriter, err := armor.Encode(buf, "PGP MESSAGE", make(map[string]string))
	if err != nil {
		return []byte{}, fmt.Errorf("Error creating OpenPGP armor: %v", err)
	}

	// Create encryptor with encoder
	encryptorWriter, err := openpgp.Encrypt(encoderWriter, []*openpgp.Entity{entity}, nil, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("Error creating entity for encryption: %v", err)
	}

	// Create compressor with encryptor

	//TODO: Removed packing with GZIP
	compressorWriter, err := gzip.NewWriterLevel(encryptorWriter, gzip.BestCompression)
	if err != nil {
		return []byte{}, fmt.Errorf("Invalid compression level: %v", err)
	}

	// Write message to compressor
	messageReader := bytes.NewReader(message)
	_, err = io.Copy(compressorWriter, messageReader)
	if err != nil {
		return []byte{}, fmt.Errorf("Error writing data to compressor: %v", err)
	}

	compressorWriter.Close()

	/*messageReader := bytes.NewReader(message)
	_, err = io.Copy(encryptorWriter, messageReader)
	if err != nil {
		return []byte{}, fmt.Errorf("Error writing data to compressor: %v", err)
	}*/
	encryptorWriter.Close()
	encoderWriter.Close()

	// Return buffer output - an encoded, encrypted, and compressed message
	return buf.Bytes(), nil
}