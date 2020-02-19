package umbral

import (
	"fmt"
	"github.com/hallazzang/aria-go"
	"github.com/stretchr/testify/require"
	"math/rand"
	"reflect"
	"testing"
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
	plainText2 := []byte("Label A Data 2")
	cipherText, capsule := Encrypt(cxt, pubKeyAliceLabelA, plainText) // enrico
	cipherText2, capsule2 := Encrypt(cxt, pubKeyAliceLabelA, plainText2) // enrico

	testDecrypt := DecryptDirect(cxt, capsule, privKeyAliceLabelA, cipherText)

	if !reflect.DeepEqual(plainText, testDecrypt) {
		t.Errorf("Direct decryption failed")
	}

	const threshold = 10
	const numSplits = 20
	kFragsForBob := SplitReKey(cxt, privKeyAliceLabelA, pubKeyBob, threshold, numSplits)

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

	// success
	testDecryptFrags := DecryptFragments(cxt, capsule, cFragsForBob, privKeyBob, pubKeyAliceLabelA, cipherText)
	if !reflect.DeepEqual(plainText, testDecryptFrags) {
		t.Errorf("Re-encapsulated fragment decryption failed")
	}

	// cFragsForBob is not ReEncapsulated for capsule2 but capsule case, occur panic
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("It should be panic, cFragsForBob is not ReEncapsulated for capsule2")
		}
	}()
	testDecryptFrags2 := DecryptFragments(cxt, capsule2, cFragsForBob, privKeyBob, pubKeyAliceLabelA, cipherText2)
	require.Nil(t, testDecryptFrags2)

	// test for add policy to another Bob(Carol) without duplicated encryption
	const threshold2 = 15
	kFragsForCarol := SplitReKey(cxt, privKeyAliceLabelA, pubKeyCarol, threshold2, numSplits)

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
		t.Errorf("Re-encapsulated fragment decryption failed 3")
	}

	// cFrags below threshold used case, occur panic
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("It should be panic, cFrags below threshold used")
		}
	}()
	testDecryptFrags = DecryptFragments(cxt, capsule, cFragsForCarol[:threshold2-1], privKeyCarol, pubKeyAliceLabelA, cipherText)
}

func ReEncapsulateWithProxyNodes(kFrags []*KFrag, capsule *Capsule, threshold, numSplits int) []*CFrag {
	proxyNodes := make([]*KFrag, threshold)
	cFrags := make([]*CFrag, threshold)

	// randomly selected proxy nodes for threshold
	perm := rand.Perm(numSplits)
	for i, v := range perm[:threshold] {
		proxyNodes[i] = kFrags[v]
	}

	// kFrags -> cFrags on each proxy nodes
	for i := range proxyNodes {
		cFrags[i] = ReEncapsulate(proxyNodes[i], capsule)
	}
	return cFrags
}

func TestAPIBasics3(t *testing.T) {

	cxt := MakeDefaultContext()

	// Label X
	privKeyAliceLabelX := GenPrivateKey(cxt)
	pubKeyAliceLabelX := privKeyAliceLabelX.GetPublicKey(cxt)

	// Label Y
	privKeyAliceLabelY := GenPrivateKey(cxt)
	pubKeyAliceLabelY := privKeyAliceLabelY.GetPublicKey(cxt)


	// Bob
	privKeyBob := GenPrivateKey(cxt)
	pubKeyBob := privKeyBob.GetPublicKey(cxt)

	data1 := []byte("Data 1")
	data2 := []byte("Data 2")

	// encrypt on Alice ( enrico )
	EncryptedData1WithX, capsule1X := Encrypt(cxt, pubKeyAliceLabelX, data1)
	EncryptedData2WithX, capsule2X := Encrypt(cxt, pubKeyAliceLabelX, data2)
	EncryptedData1WithY, capsule1Y := Encrypt(cxt, pubKeyAliceLabelY, data1)
	EncryptedData2WithY, capsule2Y := Encrypt(cxt, pubKeyAliceLabelY, data2)

	const threshold = 15
	const numSplits = 20

	// Testcases on LabelX

	// split key on Alice, and distribute to proxy nodes
	kFragsX := SplitReKey(cxt, privKeyAliceLabelX, pubKeyBob, threshold, numSplits)
	kFragsY := SplitReKey(cxt, privKeyAliceLabelY, pubKeyBob, threshold, numSplits)

	// Bob request cFrags to proxy nodes
	cFragsX1X := ReEncapsulateWithProxyNodes(kFragsX, capsule1X, threshold, numSplits)
	cFragsX2X := ReEncapsulateWithProxyNodes(kFragsX, capsule2X, threshold, numSplits)
	cFragsY1Y := ReEncapsulateWithProxyNodes(kFragsY, capsule1Y, threshold, numSplits)
	cFragsY2Y := ReEncapsulateWithProxyNodes(kFragsY, capsule2Y, threshold, numSplits)

	// Bad cases
	cFragsX1Y := ReEncapsulateWithProxyNodes(kFragsX, capsule1Y, threshold, numSplits)
	cFragsX2Y := ReEncapsulateWithProxyNodes(kFragsX, capsule2Y, threshold, numSplits)
	cFragsY1X := ReEncapsulateWithProxyNodes(kFragsY, capsule1X, threshold, numSplits)
	cFragsY2X := ReEncapsulateWithProxyNodes(kFragsY, capsule2X, threshold, numSplits)

	// result

	// success cases
	testDecryptFragsData1LabelX, r := DecryptFragmentsWithRecover(cxt, capsule1X, cFragsX1X, privKeyBob, pubKeyAliceLabelX, EncryptedData1WithX)
	require.Nil(t, r)
	require.Equal(t, data1, testDecryptFragsData1LabelX)

	testDecryptFragsData2LabelX, r := DecryptFragmentsWithRecover(cxt, capsule2X, cFragsX2X, privKeyBob, pubKeyAliceLabelX, EncryptedData2WithX)
	require.Nil(t, r)
	require.Equal(t, data2, testDecryptFragsData2LabelX)

 	testDecryptFragsData1LabelY, r := DecryptFragmentsWithRecover(cxt, capsule1Y, cFragsY1Y, privKeyBob, pubKeyAliceLabelY, EncryptedData1WithY)
	require.Nil(t, r)
	require.Equal(t, data1, testDecryptFragsData1LabelY)

	testDecryptFragsData2LabelY, r := DecryptFragmentsWithRecover(cxt, capsule2Y, cFragsY2Y, privKeyBob, pubKeyAliceLabelY, EncryptedData2WithY)
	require.Nil(t, r)
	require.Equal(t, data2, testDecryptFragsData2LabelY)

	// fail cases
	d, r := DecryptFragmentsWithRecover(cxt, capsule2X, cFragsX1X, privKeyBob, pubKeyAliceLabelX, EncryptedData1WithX)
	require.Equal(t, r, "Failed decapulation check")
	require.Nil(t, d)

	d, r = DecryptFragmentsWithRecover(cxt, capsule2X, cFragsX1X, privKeyBob, pubKeyAliceLabelY, EncryptedData2WithX)
	require.Equal(t, r, "Failed decapulation check")
	require.Nil(t, d)

	d, r = DecryptFragmentsWithRecover(cxt, capsule1X, cFragsX1X, privKeyBob, pubKeyAliceLabelY, EncryptedData1WithX)
	require.Equal(t, r, "Failed decapulation check")
	require.Nil(t, d)

	// fail, bad cases
	d, r = DecryptFragmentsWithRecover(cxt, capsule1Y, cFragsX1Y, privKeyBob, pubKeyAliceLabelY, EncryptedData1WithY)
	require.Equal(t, r, "Failed decapulation check")
	require.Nil(t, d)

	d, r = DecryptFragmentsWithRecover(cxt, capsule1Y, cFragsX1Y, privKeyBob, pubKeyAliceLabelX, EncryptedData1WithY)
	require.Equal(t, r, "Failed DEM decryption")
	require.Nil(t, d)

	d, r = DecryptFragmentsWithRecover(cxt, capsule2Y, cFragsX2Y, privKeyBob, pubKeyAliceLabelY, EncryptedData2WithY)
	require.Equal(t, r, "Failed decapulation check")
	require.Nil(t, d)

	d, r = DecryptFragmentsWithRecover(cxt, capsule2Y, cFragsX2Y, privKeyBob, pubKeyAliceLabelX, EncryptedData2WithY)
	require.Equal(t, r, "Failed DEM decryption")
	require.Nil(t, d)

	d, r = DecryptFragmentsWithRecover(cxt, capsule1X, cFragsY1X, privKeyBob, pubKeyAliceLabelY, EncryptedData1WithY)
	require.Equal(t, r, "Failed DEM decryption")
	require.Nil(t, d)

	d, r = DecryptFragmentsWithRecover(cxt, capsule1X, cFragsY1X, privKeyBob, pubKeyAliceLabelX, EncryptedData1WithY)
	require.Equal(t, r, "Failed decapulation check")
	require.Nil(t, d)

	d, r = DecryptFragmentsWithRecover(cxt, capsule2X, cFragsY2X, privKeyBob, pubKeyAliceLabelY, EncryptedData2WithX)
	require.Equal(t, r, "Failed DEM decryption")
	require.Nil(t, d)

	d, r = DecryptFragmentsWithRecover(cxt, capsule2X, cFragsY2X, privKeyBob, pubKeyAliceLabelX, EncryptedData2WithX)
	require.Equal(t, r, "Failed decapulation check")
	require.Nil(t, d)

}


// WIP
//func TestAPIAdvanced(t *testing.T) {
//	random := cryptorand.Reader
//
//	//privKeyAliceAcc := ed25519.GenPrivKey()
//	//pubKeyAliceAcc := privKeyAliceAcc.PubKey()
//	privKeyAliceRSA, err := rsa.GenerateKey(random, 256)
//	require.Nil(t, err)
//	pubKeyAliceRSA := privKeyAliceRSA.PublicKey
//
//	//cxt := MakeDefaultContext()
//
//	//privKeyAlice := GenPrivateKey(cxt)
//	//pubKeyAlice := privKeyAlice.GetPublicKey(cxt)
//
//	//privKeyBob := GenPrivateKey(cxt)
//	//pubKeyBob := privKeyBob.GetPublicKey(cxt)
//
//
//	// create random symmetric symKey
//	symKey := make([]byte, 16)
//	//rand.Seed(time.Now().UnixNano())
//	rand.Seed(time.Now().UnixNano())  // TODO: seed using Alice Key ?
//	rand.Read(symKey)
//
//	//msg := "symMsg1234567890"    // 16bytes
//
//	block, err := aes.NewCipher([]byte(symKey))
//	require.Nil(t, err)
//
//	//cipherText := make([]byte, len(msg))
//	//block.Encrypt(cipherText, []byte(msg))
//	//fmt.Printf("%x\n", cipherText)
//	//
//	//plainText := make([]byte, len(msg))
//	//block.Decrypt(plainText, cipherText)
//	//fmt.Println(string(plainText))
//	//require.Equal(t, string(plainText), msg)
//
//
//	encyptedSymKey, err := rsa.EncryptPKCS1v15(random, &pubKeyAliceRSA, symKey)
//	require.Nil(t, err)
//	decryptedSymKey, err := rsa.DecryptPKCS1v15(random, privKeyAliceRSA, encyptedSymKey)
//	require.Nil(t, err)
//
//	require.Equal(t, symKey, decryptedSymKey)
//
//
//
//	//cipherText, capsule := Encrypt(cxt, pubKeyAlice, symKey)
//	//testDecrypt := DecryptDirect(cxt, capsule, privKeyAlice, cipherText)
//	//
//	//if !reflect.DeepEqual(symKey, testDecrypt) {
//	//	t.Errorf("Direct decryption failed")
//	//}
//
//
//	plainTextM := []byte("confidential data")
//	cipherTextM := make([]byte, len(plainTextM))
//	block.Encrypt(cipherTextM, plainTextM)
//	fmt.Printf("%x\n", cipherTextM)
//
//	decryptedTextM := make([]byte, len(plainTextM))
//	block.Decrypt(decryptedTextM, cipherTextM)
//	fmt.Println(string(decryptedTextM))
//	require.Equal(t, string(decryptedTextM), plainTextM)
//
//
//	//
//	//const threshold = 10
//	//kFrags := SplitReKey(cxt, privKeyAlice, pubKeyBob, threshold, 20)
//	//
//	//cFrags := make([]*CFrag, threshold)
//	//
//	//dest := make([]*KFrag, threshold)
//	//perm := rand.Perm(threshold)
//	//for i, v := range perm {
//	//	dest[v] = kFrags[i]
//	//}
//	//
//	//for i := range dest {
//	//	cFrags[i] = ReEncapsulate(dest[i], capsule)
//	//}
//	//
//	//require.Equal(t, len(dest), threshold)
//	//
//	//testDecryptFrags := DecryptFragments(cxt, capsule, cFrags, privKeyBob, pubKeyAlice, cipherText)
//	//if !reflect.DeepEqual(plainText, testDecryptFrags) {
//	//	t.Errorf("Re-encapsulated fragment decryption failed")
//	//}
//}
//


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