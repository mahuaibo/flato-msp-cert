// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	gm "github.com/ultramesh/crypto-gm"
	"github.com/ultramesh/crypto-standard/asym"
	"github.com/ultramesh/flato-msp-cert/primitives"
	gmx509 "github.com/ultramesh/flato-msp-cert/primitives/x509"
)

// pickSignatureAlgorithm selects a signature algorithm that is compatible with
// the given public key and the list of algorithms from the peer and this side.
// The lists of signature algorithms (peerSigAlgs and ourSigAlgs) are ignored
// for tlsVersion < VersionTLS12.
//
// The returned SignatureScheme codepoint is only meaningful for TLS 1.2,
// previous TLS versions have a fixed hash function.
func pickSignatureAlgorithm(pubkey crypto.PublicKey, peerSigAlgs, ourSigAlgs []SignatureScheme, tlsVersion uint16) (sigAlg SignatureScheme, sigType uint8, hashFunc gmx509.Hash, err error) {
	if tlsVersion < VersionTLS12 || len(peerSigAlgs) == 0 {
		// For TLS 1.1 and before, the signature algorithm could not be
		// negotiated and the hash is fixed based on the signature type.
		// For TLS 1.2, if the client didn't send signature_algorithms
		// extension then we can assume that it supports SHA1. See
		// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
		switch pubkey.(type) {
		case *rsa.PublicKey:
			if tlsVersion < VersionTLS12 {
				return 0, signaturePKCS1v15, gmx509.MD5SHA1, nil
			}
			return PKCS1WithSHA1, signaturePKCS1v15, gmx509.SHA1, nil
		case *asym.ECDSAPublicKey:
			return ECDSAWithSHA1, signatureECDSA, gmx509.SHA1, nil
		case *gm.SM2PublicKey:
			return SM2WithSM3, signatureECDSA, gmx509.SM3, nil
		default:
			return 0, 0, 0, fmt.Errorf("tls: unsupported public key: %T", pubkey)
		}
	}
	for _, sigAlg := range peerSigAlgs {
		if !isSupportedSignatureAlgorithm(sigAlg, ourSigAlgs) {
			continue
		}
		hashAlg, err := lookupTLSHash(sigAlg)
		if err != nil {
			panic("tls: supported signature algorithm has an unknown hash function")
		}
		sigType := signatureFromSignatureScheme(sigAlg)
		switch pubkey.(type) {
		case *rsa.PublicKey:
			if sigType == signaturePKCS1v15 || sigType == signatureRSAPSS {
				return sigAlg, sigType, hashAlg, nil
			}
		case *asym.ECDSAPublicKey:
			if sigType == signatureECDSA && sigAlg != SM2WithSM3 {
				return sigAlg, sigType, hashAlg, nil
			}
		case *gm.SM2PublicKey:
			if sigType == signatureECDSA && sigAlg == SM2WithSM3 {
				return sigAlg, sigType, hashAlg, nil
			}
		default:
			return 0, 0, 0, fmt.Errorf("tls: unsupported public key: %T", pubkey)
		}
	}
	return 0, 0, 0, errors.New("tls: peer doesn't support any common signature algorithms")
}

// verifyHandshakeSignature verifies a signature against pre-hashed handshake
// contents.
func verifyHandshakeSignature(sigType uint8, pubkey crypto.PublicKey, hashFunc gmx509.Hash, digest, sig []byte) error {
	switch sigType {
	case signatureECDSA:
		//first, try to turn to gmx509.PublicKry
		switch key := pubkey.(type) {
		case *gm.SM2PublicKey:
			if len(sig) == 0 {
				return errors.New("tls: SM2 signature contained zero or negative values")
			}
			temp, _ := primitives.SM2Verify(key, digest, sig)
			if !temp {
				return errors.New("tls: SM2 verification failure")
			}
		case *asym.ECDSAPublicKey:
			_, err := key.Verify(nil, sig, digest)
			if err != nil {
				return errors.New("tls: ECDSA verification failure")
			}
		default:
			return errors.New("tls: ECDSA signing requires a ECDSA public key")
		}
	case signaturePKCS1v15:
		pubKey, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			return errors.New("tls: RSA signing requires a RSA public key")
		}
		if err := rsa.VerifyPKCS1v15(pubKey, crypto.Hash(hashFunc), digest, sig); err != nil {
			return err
		}
	case signatureRSAPSS:
		pubKey, ok := pubkey.(*rsa.PublicKey)
		if !ok {
			return errors.New("tls: RSA signing requires a RSA public key")
		}
		signOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
		if err := rsa.VerifyPSS(pubKey, crypto.Hash(hashFunc), digest, sig, signOpts); err != nil {
			return err
		}
	default:
		return errors.New("tls: unknown signature algorithm")
	}
	return nil
}
