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
	"bufio"
	"compress/gzip"
	_ "crypto/sha256"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	_ "golang.org/x/crypto/ripemd160"
	//"bufio"
	"io"
)

func Encrypt2(entity *openpgp.Entity, messageReader io.Reader, outfile *bufio.Writer) (*bufio.Writer, error) {
	encryptorWriter, err := openpgp.Encrypt(outfile, []*openpgp.Entity{entity}, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Error creating entity for encryption: %v", err)
	}

	_, err = io.Copy(encryptorWriter, messageReader)
	if err != nil {
		return nil, fmt.Errorf("Error writing data to compressor: %v", err)
	}
	encryptorWriter.Close()

	return outfile, nil
}

func EncryptWithArmored2(entity *openpgp.Entity, messageReader io.Reader, outfile *bufio.Writer) (*bufio.Writer, error) {

	encoderWriter, err := armor.Encode(outfile, "PGP MESSAGE", make(map[string]string))
	if err != nil {
		return nil, fmt.Errorf("Error creating OpenPGP armor: %v", err)
	}

	encryptorWriter, err := openpgp.Encrypt(encoderWriter, []*openpgp.Entity{entity}, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Error creating entity for encryption: %v", err)
	}

	_, err = io.Copy(encryptorWriter, messageReader)
	if err != nil {
		return nil, fmt.Errorf("Error writing data to compressor: %v", err)
	}
	encryptorWriter.Close()
	encoderWriter.Close()

	// Return buffer output - an encoded, encrypted, and compressed message
	return outfile, nil
}

func EncryptWithGZip2(entity *openpgp.Entity,  messageReader io.Reader, outfile *bufio.Writer) (*bufio.Writer, error) {

	encryptorWriter, err := openpgp.Encrypt(outfile, []*openpgp.Entity{entity}, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Error creating entity for encryption: %v", err)
	}

	compressorWriter, err := gzip.NewWriterLevel(encryptorWriter, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("Invalid compression level: %v", err)
	}

	_, err = io.Copy(compressorWriter, messageReader)
	if err != nil {
		return nil, fmt.Errorf("Error writing data to compressor: %v", err)
	}

	compressorWriter.Close()
	encryptorWriter.Close()

	// Return buffer output - an encoded, encrypted, and compressed message
	return outfile, nil
}

func EncryptWithArmoredAndGZip2(entity *openpgp.Entity, messageReader io.Reader, outfile *bufio.Writer) (*bufio.Writer, error) {

	encoderWriter, err := armor.Encode(outfile, "PGP MESSAGE", make(map[string]string))
	if err != nil {
		return nil, fmt.Errorf("Error creating OpenPGP armor: %v", err)
	}

	encryptorWriter, err := openpgp.Encrypt(encoderWriter, []*openpgp.Entity{entity}, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Error creating entity for encryption: %v", err)
	}

	compressorWriter, err := gzip.NewWriterLevel(encryptorWriter, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("Invalid compression level: %v", err)
	}

	_, err = io.Copy(compressorWriter, messageReader)
	if err != nil {
		return nil, fmt.Errorf("Error writing data to compressor: %v", err)
	}

	compressorWriter.Close()
	encryptorWriter.Close()
	encoderWriter.Close()

	return outfile, nil
}