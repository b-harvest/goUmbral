package umbral

import (
	"crypto/aes"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/hallazzang/aria-go"
	"github.com/stretchr/testify/require"
	"math/rand"
	"reflect"
	"testing"
	"time"
	//"github.com/tendermint/tendermint/crypto"
	//"github.com/tendermint/tendermint/crypto/ed25519"
)

func TestAPIBasics(t *testing.T) {

	cxt := MakeDefaultContext()

	privKeyAlice := GenPrivateKey(cxt)
	pubKeyAlice := privKeyAlice.GetPublicKey(cxt)

	privKeyBob := GenPrivateKey(cxt)
	pubKeyBob := privKeyBob.GetPublicKey(cxt)

	plainText := []byte("attack at dawn")
	cipherText, capsule := Encrypt(cxt, pubKeyAlice, plainText) // enrico

	testDecrypt := DecryptDirect(cxt, capsule, privKeyAlice, cipherText)

	if !reflect.DeepEqual(plainText, testDecrypt) {
		t.Errorf("Direct decryption failed")
	}

	const threshold = 10
	kFrags := SplitReKey(cxt, privKeyAlice, pubKeyBob, threshold, 20)

	cFrags := make([]*CFrag, threshold)

	dest := make([]*KFrag, threshold)
	perm := rand.Perm(threshold)
	for i, v := range perm {
		dest[v] = kFrags[i]
	}

	for i := range dest {
		cFrags[i] = ReEncapsulate(dest[i], capsule)
	}

	require.Equal(t, len(dest), threshold)

	testDecryptFrags := DecryptFragments(cxt, capsule, cFrags, privKeyBob, pubKeyAlice, cipherText)
	if !reflect.DeepEqual(plainText, testDecryptFrags) {
		t.Errorf("Re-encapsulated fragment decryption failed")
	}
}

func TestAPIBasics2(t *testing.T) {

	cxt := MakeDefaultContext()

	// Label A
	privKeyAliceLabelA := GenPrivateKey(cxt)
	pubKeyAliceLabelA := privKeyAliceLabelA.GetPublicKey(cxt)

	privKeyBob := GenPrivateKey(cxt)
	pubKeyBob := privKeyBob.GetPublicKey(cxt)

	privKeyCarol := GenPrivateKey(cxt)
	pubKeyCarol := privKeyCarol.GetPublicKey(cxt)

	plainText := []byte("Label A Data 1")
	cipherText, capsule := Encrypt(cxt, pubKeyAliceLabelA, plainText) // enrico

	testDecrypt := DecryptDirect(cxt, capsule, privKeyAliceLabelA, cipherText)

	if !reflect.DeepEqual(plainText, testDecrypt) {
		t.Errorf("Direct decryption failed")
	}

	const threshold = 10
	kFragsForBob := SplitReKey(cxt, privKeyAliceLabelA, pubKeyBob, threshold, 20)

	cFragsForBob := make([]*CFrag, threshold)
	dest := make([]*KFrag, threshold)
	perm := rand.Perm(threshold)
	for i, v := range perm {
		dest[v] = kFragsForBob[i]
	}

	for i := range dest {
		cFragsForBob[i] = ReEncapsulate(dest[i], capsule)
	}
	require.Equal(t, len(dest), threshold)

	testDecryptFrags := DecryptFragments(cxt, capsule, cFragsForBob, privKeyBob, pubKeyAliceLabelA, cipherText)
	if !reflect.DeepEqual(plainText, testDecryptFrags) {
		t.Errorf("Re-encapsulated fragment decryption failed")
	}

	const threshold2 = 15
	kFragsForCarol := SplitReKey(cxt, privKeyAliceLabelA, pubKeyCarol, threshold2, 20)

	cFragsForCarol := make([]*CFrag, threshold2)
	dest = make([]*KFrag, threshold2)
	perm = rand.Perm(threshold2)
	for i, v := range perm {
		dest[v] = kFragsForCarol[i]
	}

	for i := range dest {
		cFragsForCarol[i] = ReEncapsulate(dest[i], capsule)
	}
	require.Equal(t, len(dest), threshold2)

	testDecryptFrags = DecryptFragments(cxt, capsule, cFragsForCarol, privKeyCarol, pubKeyAliceLabelA, cipherText)
	if !reflect.DeepEqual(plainText, testDecryptFrags) {
		t.Errorf("Re-encapsulated fragment decryption failed 2")
	}

	// occur panic, cFrags below threshold used
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("It should be panic, cFrags below threshold used")
		}
	}()
	testDecryptFrags = DecryptFragments(cxt, capsule, cFragsForCarol[:threshold2-1], privKeyCarol, pubKeyAliceLabelA, cipherText)
}

// WIP
func TestAPIAdvanced(t *testing.T) {
	random := cryptorand.Reader

	//privKeyAliceAcc := ed25519.GenPrivKey()
	//pubKeyAliceAcc := privKeyAliceAcc.PubKey()
	privKeyAliceRSA, err := rsa.GenerateKey(random, 256)
	require.Nil(t, err)
	pubKeyAliceRSA := privKeyAliceRSA.PublicKey

	//cxt := MakeDefaultContext()

	//privKeyAlice := GenPrivateKey(cxt)
	//pubKeyAlice := privKeyAlice.GetPublicKey(cxt)

	//privKeyBob := GenPrivateKey(cxt)
	//pubKeyBob := privKeyBob.GetPublicKey(cxt)


	// create random symmetric symKey
	symKey := make([]byte, 16)
	//rand.Seed(time.Now().UnixNano())
	rand.Seed(time.Now().UnixNano())  // TODO: seed using Alice Key ?
	rand.Read(symKey)

	//msg := "symMsg1234567890"    // 16bytes

	block, err := aes.NewCipher([]byte(symKey))
	require.Nil(t, err)

	//cipherText := make([]byte, len(msg))
	//block.Encrypt(cipherText, []byte(msg))
	//fmt.Printf("%x\n", cipherText)
	//
	//plainText := make([]byte, len(msg))
	//block.Decrypt(plainText, cipherText)
	//fmt.Println(string(plainText))
	//require.Equal(t, string(plainText), msg)


	encyptedSymKey, err := rsa.EncryptPKCS1v15(random, &pubKeyAliceRSA, symKey)
	require.Nil(t, err)
	decryptedSymKey, err := rsa.DecryptPKCS1v15(random, privKeyAliceRSA, encyptedSymKey)
	require.Nil(t, err)

	require.Equal(t, symKey, decryptedSymKey)



	//cipherText, capsule := Encrypt(cxt, pubKeyAlice, symKey)
	//testDecrypt := DecryptDirect(cxt, capsule, privKeyAlice, cipherText)
	//
	//if !reflect.DeepEqual(symKey, testDecrypt) {
	//	t.Errorf("Direct decryption failed")
	//}


	plainTextM := []byte("confidential data")
	cipherTextM := make([]byte, len(plainTextM))
	block.Encrypt(cipherTextM, plainTextM)
	fmt.Printf("%x\n", cipherTextM)

	decryptedTextM := make([]byte, len(plainTextM))
	block.Decrypt(decryptedTextM, cipherTextM)
	fmt.Println(string(decryptedTextM))
	require.Equal(t, string(decryptedTextM), plainTextM)


	//
	//const threshold = 10
	//kFrags := SplitReKey(cxt, privKeyAlice, pubKeyBob, threshold, 20)
	//
	//cFrags := make([]*CFrag, threshold)
	//
	//dest := make([]*KFrag, threshold)
	//perm := rand.Perm(threshold)
	//for i, v := range perm {
	//	dest[v] = kFrags[i]
	//}
	//
	//for i := range dest {
	//	cFrags[i] = ReEncapsulate(dest[i], capsule)
	//}
	//
	//require.Equal(t, len(dest), threshold)
	//
	//testDecryptFrags := DecryptFragments(cxt, capsule, cFrags, privKeyBob, pubKeyAlice, cipherText)
	//if !reflect.DeepEqual(plainText, testDecryptFrags) {
	//	t.Errorf("Re-encapsulated fragment decryption failed")
	//}
}



func TestAria(t *testing.T) {
	// ARIA encryption test case A.3. 256-Bit Key from https://tools.ietf.org/html/rfc5794
	key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
	plaintext := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	block, err := aria.NewCipher(key)
	require.Nil(t, err)

	fmt.Printf("plaintext: %x\n", plaintext)

	ciphertext := make([]byte, 16)
	block.Encrypt(ciphertext, plaintext)
	fmt.Printf("ciphertext: % x\n", ciphertext)

	decrypted := make([]byte, 16)
	block.Decrypt(decrypted, ciphertext)
	fmt.Printf("decrypted: %x\n", decrypted)
}