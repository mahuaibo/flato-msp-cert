package primitives

import (
	"crypto"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	gm "github.com/ultramesh/crypto-gm"
	"github.com/ultramesh/crypto-standard/asym"
	gmx509 "github.com/ultramesh/flato-msp-cert/primitives/x509"
	"github.com/ultramesh/flato-msp-cert/primitives/x509/pkix"
	"math/big"
	"reflect"
	"strings"
	"time"
)

//ParseCertificate already support ra
func ParseCertificate(cert []byte) (*gmx509.Certificate, error) {
	//if input is pem format, try to parse
	block, _ := pem.Decode(cert)

	if block != nil {
		cert = block.Bytes
	}

	x509Cert, err := gmx509.ParseCertificate(cert)

	if err != nil {
		return nil, err
	}

	return x509Cert, nil
}

//VerifyCert already support ra
func VerifyCert(cert *gmx509.Certificate, ca *gmx509.Certificate) (bool, error) {
	if cert.NotBefore.After(time.Now()) || cert.NotAfter.Before(time.Now()) {
		return false, errors.New("this cert is expired")
	}

	err := cert.CheckSignatureFrom(ca)
	if err != nil {
		return false, err
	}

	return true, nil
}

//MarshalCertificate Marshal Certificate
func MarshalCertificate(template *gmx509.Certificate, useGruomi bool) (cert []byte, err error) {
	return gmx509.MarshalCertificate(template, useGruomi)
}

//GenCert generate ecert
func GenCert(ca *gmx509.Certificate, privatekey crypto.Signer, publicKey crypto.PublicKey,
	o, cn, gn string, isCA bool) ([]byte, error) {

	if !reflect.DeepEqual(ca.PublicKey, privatekey.Public()) {
		return nil, errors.New("public key in ca does not match private key")
	}

	return createCertByCaAndPublicKey(ca, privatekey, publicKey, isCA, o, cn, gn)
}

//NewSelfSignedCert generate self-signature certificate
func NewSelfSignedCert(o, cn, gn string, useGuomi bool) (
	[]byte, interface{}, error) {
	var (
		err                error
		privKeyECDSA       *asym.ECDSAPrivateKey
		privKeySM          *gm.SM2PrivateKey
		signatureAlgorithm gmx509.SignatureAlgorithm
		privKey            crypto.Signer
		pubKey             interface{}
	)
	if useGuomi {
		privKeySM, err = gm.GenerateSM2Key()
		if err != nil {
			return nil, nil, err
		}
		signatureAlgorithm = gmx509.SM3WithSM2
		privKey = privKeySM
		pubKey = privKeySM.Public()
	} else {
		privKeyECDSA, err = asym.GenerateKey(asym.AlgoP256R1)
		if err != nil {
			return nil, nil, err
		}
		signatureAlgorithm = gmx509.ECDSAWithSHA256
		privKey = privKeyECDSA
		pubKey = privKeyECDSA.Public()
	}

	testExtKeyUsage := []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageClientAuth, gmx509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}

	gn = strings.ToLower(gn)
	if gn != "ecert" && gn != "rcert" && gn != "sdkcert" && gn != "" {
		return nil, nil, errors.New("gn should be one of ecert, rcert or sdkcert or empty")
	}
	Subject := pkix.Name{
		CommonName:   cn,
		Organization: []string{o},
		Country:      []string{"CHN"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			// This should override the Country, above.
			{
				Type:  []int{2, 5, 4, 6},
				Value: "ZH",
			},
		},
	}
	if gn != "" {
		Subject.ExtraNames = append(Subject.ExtraNames,
			pkix.AttributeTypeAndValue{
				Type:  []int{2, 5, 4, 42},
				Value: gn,
			})
	}

	template := gmx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      Subject,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(876000 * time.Hour), //暂定证书有效期为100年

		SignatureAlgorithm: signatureAlgorithm,

		SubjectKeyID: []byte{1, 2, 3, 4},
		KeyUsage:     gmx509.KeyUsageCertSign | gmx509.KeyUsageDigitalSignature,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	cert, err := gmx509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey, useGuomi)
	if err != nil {
		return nil, nil, err
	}

	return cert, privKey, nil
}

//SelfSignedCert generate self-signature certificate by privKey and pubKey
func SelfSignedCert(o, cn, gn string, useGuomi bool, priv []byte, pub []byte) (
	[]byte, error) {
	var (
		err                error
		signatureAlgorithm gmx509.SignatureAlgorithm
		privKey            interface{}
		pubKey             interface{}
	)

	privKey, err = UnmarshalPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pubKey, err = UnmarshalPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if useGuomi {
		signatureAlgorithm = gmx509.SM3WithSM2
		_, ok := privKey.(*gm.SM2PrivateKey)
		if !ok {
			return nil, errors.New("private key is not sm2 key")
		}
	} else {
		signatureAlgorithm = gmx509.ECDSAWithSHA256
		_, ok := privKey.(*asym.ECDSAPrivateKey)
		if !ok {
			return nil, errors.New("private key is not ecdsa key")
		}
	}

	testExtKeyUsage := []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageClientAuth, gmx509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}

	gn = strings.ToLower(gn)
	if gn != "ecert" && gn != "rcert" && gn != "sdkcert" && gn != "" {
		return nil, errors.New("gn should be one of ecert, rcert or sdkcert or empty")
	}
	Subject := pkix.Name{
		CommonName:   cn,
		Organization: []string{o},
		Country:      []string{"CHN"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			// This should override the Country, above.
			{
				Type:  []int{2, 5, 4, 6},
				Value: "ZH",
			},
		},
	}
	if gn != "" {
		Subject.ExtraNames = append(Subject.ExtraNames,
			pkix.AttributeTypeAndValue{
				Type:  []int{2, 5, 4, 42},
				Value: gn,
			})
	}

	template := gmx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      Subject,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(876000 * time.Hour), //暂定证书有效期为100年

		SignatureAlgorithm: signatureAlgorithm,

		SubjectKeyID: []byte{1, 2, 3, 4},
		KeyUsage:     gmx509.KeyUsageCertSign | gmx509.KeyUsageDigitalSignature,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	cert, err := gmx509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey.(crypto.Signer), useGuomi)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func createCertByCaAndPublicKey(ca *gmx509.Certificate, caPrivate crypto.Signer, subPublic crypto.PublicKey, isCa bool, o, cn, gn string) (certDER []byte, err error) {
	var (
		signatureAlgorithm gmx509.SignatureAlgorithm
		useGuomi           bool
	)

	//If the private key of ca is sm2,
	// the generated private key of the cert is also sm2.
	switch caPrivate.(type) {
	case *gm.SM2PrivateKey:
		useGuomi = true
		signatureAlgorithm = gmx509.SM3WithSM2
	case *asym.ECDSAPrivateKey:
		useGuomi = false
		signatureAlgorithm = gmx509.ECDSAWithSHA256
	default:
		return nil, errors.New("private neither *gmx509.PrivateKey nor *ecdsa.PrivateKey")
	}

	testExtKeyUsage := []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageClientAuth, gmx509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	gn = strings.ToLower(gn)
	if gn != "ecert" && gn != "rcert" && gn != "sdkcert" && gn != "" {
		return nil, errors.New("gn should be one of ecert, rcert or sdkcert or empty")
	}
	Subject := pkix.Name{
		CommonName:   cn,
		Organization: []string{o},
		Country:      []string{"CHN"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			// This should override the Country, above.
			{
				Type:  []int{2, 5, 4, 6},
				Value: "ZH",
			},
		},
	}
	t := UnknownCertType
	if gn != "" {
		switch gn {
		case "ecert":
			t = ECert
		case "rcert":
			t = RCert
		case "sdkcert":
			t = SDKCert
		}
		Subject.ExtraNames = append(Subject.ExtraNames,
			pkix.AttributeTypeAndValue{
				Type:  []int{2, 5, 4, 42},
				Value: gn,
			})
	}
	template := gmx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      Subject,

		//The expiration time of cert is based on ca
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  ca.NotAfter,

		SignatureAlgorithm: signatureAlgorithm,

		SubjectKeyID: []byte{1, 2, 3, 4},
		KeyUsage:     gmx509.KeyUsageCertSign | gmx509.KeyUsageDigitalSignature,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  isCa,
	}

	if t != UnknownCertType {
		template.ExtraExtensions = append(template.ExtraExtensions,
			pkix.Extension{
				ID:    CertTypeOID,
				Value: t.GetValue(),
			})
	}

	cert, err := gmx509.CreateCertificate(rand.Reader, &template, ca, subPublic, caPrivate, useGuomi)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
