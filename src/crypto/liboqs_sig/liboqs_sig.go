package liboqs_sig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"io"
	"crypto/rand"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"golang.org/x/crypto/cryptobyte"
)

// ID identifies each type of Hybrid Signature.
type ID uint16

const (
	P256_Dilithium2 ID = 0x01fb
)

// type LiboqsHybridSig struct {
// 	pqcName string  // Passed as argument to oqs.KeyEncapsulation.Init()
// 	classic elliptic.Curve
// 	pqc     oqs.Signature
// }

type PublicKey struct {
	SigId ID
	classic *ecdsa.PublicKey 
	pqc []byte
}

type PrivateKey struct {
	SigId ID
	classic *ecdsa.PrivateKey	
	pqc []byte
	hybridPub *PublicKey
}


// Private Key methods
// Implementing the crypto.Signer interface

func (priv *PrivateKey) Public() *PublicKey {
	return priv.hybridPub
}


func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {

	classicSig, err := priv.classic.Sign(rand, digest, opts)
	if err != nil {
		return nil, err
	}

	pqcSigner := oqs.Signature{}

	if err := pqcSigner.Init(sigIdtoName[priv.SigId], priv.pqc); err != nil {
		return nil, err
	}

	pqcSig, err := pqcSigner.Sign(digest)
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	
	b.AddUint16(uint16(len(classicSig)))
	b.AddBytes(classicSig)
	b.AddUint16(uint16(len(pqcSig)))
	b.AddBytes(pqcSig)


	return b.BytesOrPanic(), nil
}

// Public Key methods

func (pub *PublicKey) MarshalBinary() ([]byte) {
	var b cryptobyte.Builder
	
	classicPubBytes := elliptic.Marshal(pub.classic.Curve, pub.classic.X, pub.classic.Y)
		
	// JP - Info: Following MarshalBinary() in crypto/kem
	b.AddUint16(uint16(pub.SigId))
	b.AddBytes(classicPubBytes)  // JP: Classic bytes
	b.AddBytes(pub.pqc)  // JP: PQC bytes

	return b.BytesOrPanic()
}

func (pub *PublicKey) Verify(signed, sig []byte) (bool, error) {

	classicSize := binary.BigEndian.Uint16(sig[:2])
	classicSig := sig[2:classicSize]

	pqcSize := binary.BigEndian.Uint16(sig[classicSize:classicSize+2])
	pqcSig := sig[classicSize+2:pqcSize]

	classicValid := ecdsa.VerifyASN1(pub.classic, signed, classicSig)

	verifier := oqs.Signature{}

	if err := verifier.Init(sigIdtoName[pub.SigId], nil); err != nil {
		return false, err
	}

	pqcValid, err := verifier.Verify(signed, pqcSig, pub.pqc)
	if err != nil {
		return false, err
	}

	if classicValid && pqcValid {
		return true, nil
	}

	return false, nil
}


// Package Functions

func GenerateKey(sigId ID) (*PublicKey, *PrivateKey, error) {

	var curve elliptic.Curve

	switch true {
	case sigId >= P256_Dilithium2 && sigId <= P256_Dilithium2:
		curve = elliptic.P256()
	default:
		return nil, nil, errors.New("bad signature id")		
	}

	// Classic
	classicPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	classicPub := &classicPriv.PublicKey

	// PQC

	oqsSignature := oqs.Signature{}

	if err := oqsSignature.Init(sigIdtoName[sigId], nil); err != nil {
		return nil, nil, err
	}

	pqcPub, err := oqsSignature.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	pqcPriv := oqsSignature.ExportSecretKey()

	// Hybrid Keypair

	pub := new(PublicKey)
	priv := new(PrivateKey)

	pub.SigId = sigId
	pub.classic = classicPub
	pub.pqc = pqcPub

	priv.SigId = sigId
	priv.classic = classicPriv
	priv.pqc = pqcPriv
	priv.hybridPub = pub


	return pub, priv, nil
}


// func (sch *LiboqsHybridSig) GenerateKey() (*PublicKey, *PrivateKey, error) {

// 	// Classic
// 	classicPriv, err := ecdsa.GenerateKey(sch.classic, rand.Reader)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	classicPub := classicPriv.Public()

// 	// PQC

// 	if err := sch.pqc.Init(sch.pqcName, nil); err != nil {
// 		return nil, nil, err
// 	}

// 	pqcPub, err := sch.pqc.GenerateKeyPair()
// 	if err != nil {
// 	}

// 	pqcPriv := sch.pqc.ExportSecretKey()

// 	// JP - TODO: Check this return. Where is the PublicKey in the memory?
// 	return &PublicKey{classic: classicPub, pqc: pqcPub}, &PrivateKey{classic: classicPriv, pqc: pqcPriv, hybridPub: }, nil
// }


var sigIdtoName = map[ID]string {
	P256_Dilithium2: "Dilithium2",
}