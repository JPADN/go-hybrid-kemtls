package kem

import (
	"circl/hpke"
	"circl/kem"
	"fmt"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// Scheme for a Liboqs hybrid KEM.

type liboqsScheme struct {
	pqcName   string       // Passed as argument to oqs.KeyEncapsulation.Init()
	classic   kem.Scheme
	pqc 		  oqs.KeyEncapsulation
}

// JP: TODO: Should I use a pointer?
var p256_ntru_hps_2048_509 liboqsScheme = liboqsScheme{
	"NTRU-HPS-2048-509",
	hpke.KEM_P256_HKDF_SHA256.Scheme(),
	oqs.KeyEncapsulation{},
}

func getLiboqsScheme(kemID ID) liboqsScheme {
	var scheme liboqsScheme
	
	switch kemID {
	case P256_NTRU_HPS_2048_509:
		scheme = p256_ntru_hps_2048_509
	}
	return scheme
}


func (sch *liboqsScheme) Keygen() ([]byte, []byte, error) {
	
	// Classic
	kemPk1, kemSk1, err := sch.classic.GenerateKeyPair()  // using kem.Scheme interface from circl/kem/kem.go
	if err != nil {
		return nil, nil, err
	}

	pk1, err := kemPk1.MarshalBinary();
	if err != nil {
		return nil, nil, err
	}
	
	sk1, err := kemSk1.MarshalBinary();	
	if err != nil {
		return nil, nil, err
	}

	// PQC

	// defer keyEncaps.Clean()  // When uncommented, the shared secrets do not match
	
	if err := sch.pqc.Init(sch.pqcName, nil); err != nil {
		return nil, nil, err
	}

	pk2, err := sch.pqc.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	sk2 := sch.pqc.ExportSecretKey()


	return append(pk1, pk2...), append(sk1, sk2...), nil
}

func (sch *liboqsScheme) Encapsulate(pk *PublicKey) ([]byte, []byte, error) {
	
	if err := sch.pqc.Init(sch.pqcName, nil); err != nil {
		return nil, nil, err
	}

	classicPk := pk.PublicKey[0:sch.classic.PublicKeySize()]
	pqcPk := pk.PublicKey[sch.classic.PublicKeySize():]
	
	// Classic
	pk1, err := sch.classic.UnmarshalBinaryPublicKey(classicPk)
	if err != nil {
		return nil, nil, err
	}

	ct1, ss1, err := sch.classic.Encapsulate(pk1)
	if err != nil {
		return nil, nil, err
	}

	// PQC

	ct2, ss2, err := sch.pqc.EncapSecret(pqcPk)
	if err != nil {
		return nil, nil, err
	}

	return append(ct1, ct2...), append(ss1, ss2...), nil
}

func (sch *liboqsScheme) Decapsulate(sk *PrivateKey, ct []byte) ([]byte, error) {
	
	fmt.Println(len(sk.PrivateKey))
	fmt.Println(cap(sk.PrivateKey))
	fmt.Println(len(ct))
	fmt.Println(cap(ct))
	fmt.Println(sch.classic.PrivateKeySize())
	fmt.Println(sch.pqc.Details().LengthSecretKey)
	fmt.Println(sch.classic.CiphertextSize())
	fmt.Println(sch.pqc.Details().LengthCiphertext)

	classicSk := sk.PrivateKey[0:sch.classic.PrivateKeySize()]
	pqcSk := sk.PrivateKey[sch.classic.PrivateKeySize():]

	classicCt := ct[0:sch.classic.CiphertextSize()]
	pqcCt := ct[sch.classic.CiphertextSize():]
	
	sk1, err := sch.classic.UnmarshalBinaryPrivateKey(classicSk)
	if err != nil {
		return nil, err
	}

	classicSS, err := sch.classic.Decapsulate(sk1, classicCt)
	if err != nil {
		return nil, err
	}

	if err := sch.pqc.Init(sch.pqcName, pqcSk); err != nil {
		return nil, err
	}

	pqcSS, err := sch.pqc.DecapSecret(pqcCt)
	if err != nil {
		return nil, err
	}

	return append(classicSS, pqcSS...), nil
}
