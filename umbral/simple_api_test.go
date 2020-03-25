package umbral

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/hallazzang/aria-go"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/secp256k1"
	"math/big"
	"math/rand"
	"reflect"
	"testing"
)

// from github.com/tendermint/tendermint/crypto/secp256k1/secp256k1_test.go
type keyData struct {
	priv string
	pub  string
	addr string
	privBytes []byte
}

var secpDataTable = []keyData{
	{
		priv: "a96e62ed3955e65be32703f12d87b6b5cf26039ecfa948dc5107a495418e5330",
		pub:  "02950e1cdfcb133d6024109fd489f734eeb4502418e538c28481f22bce276f248c",
		addr: "1CKZ9Nx4zgds8tU7nJHotKSDr4a9bYJCa3",
		privBytes: []byte{169,110,98,237,57,85,230,91,227,39,3,241,45,135,182,181,207,38,3,158,207,169,72,220,81,7,164,149,65,142,83,48},
	},
}

func toByteArray(input secp256k1.PubKeySecp256k1) []byte {
	var output []byte
	for _, v := range input {
		output = append(output, v)
	}
	return output
}

func TestPubKeySecp256k1Address(t *testing.T) {
	ctx := MakeDefaultContext()
	for _, dt := range secpDataTable {
		tPrivKey, _ := hex.DecodeString(dt.priv)
		//pubB, _ := hex.DecodeString(d.pub)

		var priv secp256k1.PrivKeySecp256k1
		copy(priv[:], tPrivKey)

		d := new(big.Int)
		d.SetBytes(tPrivKey)

		tPubKey := priv.PubKey()
		tPubKeyBytes, _ := tPubKey.(secp256k1.PubKeySecp256k1)
		tPubKeyBytes2 := toByteArray(tPubKeyBytes)
		//tPubKeyBytes3 := tPubKeyBytes.Bytes()

		uPrivKey := GenPrivateKeyFromBytes(ctx, dt.privBytes)
		uPubKey := uPrivKey.GetPublicKey(ctx)
		uPubkeyBytes := uPubKey.toBytes(true)
		res := bytes.Compare(tPubKeyBytes2, uPubkeyBytes)
		require.Equal(t, res, 0)
		require.Equal(t, tPubKeyBytes2, uPubkeyBytes)
	}
}

func TestKeyPair(t *testing.T) {

	ctx := MakeDefaultContext()
	privKeyAlice := GenPrivateKey(ctx)
	pubKeyAlice := privKeyAlice.GetPublicKey(ctx)

	pkey := []byte{169,110,98,237,57,85,230,91,227,39,3,241,45,135,182,181,207,38,3,158,207,169,72,220,81,7,164,149,65,142,83,48}
	privKeyAlice2 := GenPrivateKeyFromBytes(ctx, pkey)
	pubKeyAlice2 := privKeyAlice2.GetPublicKey(ctx)
	pubkeyBytes2 := pubKeyAlice2.toBytes(true)
	fmt.Println(privKeyAlice, pubKeyAlice, privKeyAlice2, pubKeyAlice2, pubkeyBytes2)
}

func TestAPIBasics(t *testing.T) {

	ctx := MakeDefaultContext()

	privKeyAlice := GenPrivateKey(ctx)
	pubKeyAlice := privKeyAlice.GetPublicKey(ctx)

	privKeyBob := GenPrivateKey(ctx)
	pubKeyBob := privKeyBob.GetPublicKey(ctx)

	plainText := []byte("attack at dawn")
	cipherText, capsule := Encrypt(ctx, pubKeyAlice, plainText) // enrico

	testDecrypt := DecryptDirect(ctx, capsule, privKeyAlice, cipherText)

	if !reflect.DeepEqual(plainText, testDecrypt) {
		t.Errorf("Direct decryption failed")
	}

	const threshold = 10
	kFrags := SplitReKey(ctx, privKeyAlice, pubKeyBob, threshold, 20)

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

	testDecryptFrags := DecryptFragments(ctx, capsule, cFrags, privKeyBob, pubKeyAlice, cipherText)
	if !reflect.DeepEqual(plainText, testDecryptFrags) {
		t.Errorf("Re-encapsulated fragment decryption failed")
	}
}

func TestAPIBasics2(t *testing.T) {

	ctx := MakeDefaultContext()

	// Label A
	privKeyAliceLabelA := GenPrivateKey(ctx)
	pubKeyAliceLabelA := privKeyAliceLabelA.GetPublicKey(ctx)

	privKeyBob := GenPrivateKey(ctx)
	pubKeyBob := privKeyBob.GetPublicKey(ctx)

	privKeyCarol := GenPrivateKey(ctx)
	pubKeyCarol := privKeyCarol.GetPublicKey(ctx)

	plainText := []byte("Label A Data 1")
	plainText2 := []byte("Label A Data 2")
	cipherText, capsule := Encrypt(ctx, pubKeyAliceLabelA, plainText) // enrico
	cipherText2, capsule2 := Encrypt(ctx, pubKeyAliceLabelA, plainText2) // enrico

	testDecrypt := DecryptDirect(ctx, capsule, privKeyAliceLabelA, cipherText)

	if !reflect.DeepEqual(plainText, testDecrypt) {
		t.Errorf("Direct decryption failed")
	}

	const threshold = 10
	const numSplits = 20
	kFragsForBob := SplitReKey(ctx, privKeyAliceLabelA, pubKeyBob, threshold, numSplits)

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
	testDecryptFrags := DecryptFragments(ctx, capsule, cFragsForBob, privKeyBob, pubKeyAliceLabelA, cipherText)
	if !reflect.DeepEqual(plainText, testDecryptFrags) {
		t.Errorf("Re-encapsulated fragment decryption failed")
	}

	// cFragsForBob is not ReEncapsulated for capsule2 but capsule case, occur panic
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("It should be panic, cFragsForBob is not ReEncapsulated for capsule2")
		}
	}()
	testDecryptFrags2 := DecryptFragments(ctx, capsule2, cFragsForBob, privKeyBob, pubKeyAliceLabelA, cipherText2)
	require.Nil(t, testDecryptFrags2)

	// test for add policy to another Bob(Carol) without duplicated encryption
	const threshold2 = 15
	kFragsForCarol := SplitReKey(ctx, privKeyAliceLabelA, pubKeyCarol, threshold2, numSplits)

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

	testDecryptFrags = DecryptFragments(ctx, capsule, cFragsForCarol, privKeyCarol, pubKeyAliceLabelA, cipherText)
	if !reflect.DeepEqual(plainText, testDecryptFrags) {
		t.Errorf("Re-encapsulated fragment decryption failed 3")
	}

	// cFrags below threshold used case, occur panic
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("It should be panic, cFrags below threshold used")
		}
	}()
	testDecryptFrags = DecryptFragments(ctx, capsule, cFragsForCarol[:threshold2-1], privKeyCarol, pubKeyAliceLabelA, cipherText)
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


func TestAPIBasics4(t *testing.T) {

	cxt := MakeDefaultContext()

	// Label X
	privKeyAliceLabelX := GenPrivateKey(cxt)
	pubKeyAliceLabelX := privKeyAliceLabelX.GetPublicKey(cxt)

	// Bob
	privKeyBob := GenPrivateKey(cxt)
	pubKeyBob := privKeyBob.GetPublicKey(cxt)

	// Carol
	privKeyCarol := GenPrivateKey(cxt)
	pubKeyCarol := privKeyCarol.GetPublicKey(cxt)

	data1 := []byte("Data 1")
	data2 := []byte("Data 2")

	// encrypt on Alice ( enrico )
	EncryptedData1, capsule1 := Encrypt(cxt, pubKeyAliceLabelX, data1)
	EncryptedData2, capsule2 := Encrypt(cxt, pubKeyAliceLabelX, data2)

	const threshold = 15
	const numSplits = 20

	// split key on Alice, and distribute to proxy nodes
	kFragsB := SplitReKey(cxt, privKeyAliceLabelX, pubKeyBob, threshold, numSplits)
	kFragsC := SplitReKey(cxt, privKeyAliceLabelX, pubKeyCarol, threshold, numSplits)

	// TODO: policy check
	// Bob request cFrags to proxy nodes
	cFragsB1 := ReEncapsulateWithProxyNodes(kFragsB, capsule1, threshold, numSplits)
	cFragsB2 := ReEncapsulateWithProxyNodes(kFragsB, capsule2, threshold, numSplits)

	// Carol request cFrags to proxy nodes
	cFragsC1 := ReEncapsulateWithProxyNodes(kFragsC, capsule1, threshold, numSplits)
	cFragsC2 := ReEncapsulateWithProxyNodes(kFragsC, capsule2, threshold, numSplits)

	// Bad cases
	//cFragsY1X := ReEncapsulateWithProxyNodes(kFragsY, capsule1X, threshold, numSplits)
	//cFragsY2X := ReEncapsulateWithProxyNodes(kFragsY, capsule2X, threshold, numSplits)

	// result

	// success cases
	testDecryptFragsB1, r := DecryptFragmentsWithRecover(cxt, capsule1, cFragsB1, privKeyBob, pubKeyAliceLabelX, EncryptedData1)
	require.Nil(t, r)
	require.Equal(t, data1, testDecryptFragsB1)

	testDecryptFragsC1, r := DecryptFragmentsWithRecover(cxt, capsule1, cFragsC1, privKeyCarol, pubKeyAliceLabelX, EncryptedData1)
	require.Nil(t, r)
	require.Equal(t, data1, testDecryptFragsC1)


	testDecryptFragsB2, r := DecryptFragmentsWithRecover(cxt, capsule2, cFragsB2, privKeyBob, pubKeyAliceLabelX, EncryptedData2)
	require.Nil(t, r)
	require.Equal(t, data2, testDecryptFragsB2)

	testDecryptFragsC2, r := DecryptFragmentsWithRecover(cxt, capsule2, cFragsC2, privKeyCarol, pubKeyAliceLabelX, EncryptedData2)
	require.Nil(t, r)
	require.Equal(t, data2, testDecryptFragsC2)


	d, r := DecryptFragmentsWithRecover(cxt, capsule1, cFragsC1, privKeyCarol, pubKeyAliceLabelX, EncryptedData2)
	require.Equal(t, r, "Failed DEM decryption")
	require.Nil(t, d)


	//testDecryptFragsData2LabelX, r := DecryptFragmentsWithRecover(cxt, capsule2X, cFragsX2X, privKeyBob, pubKeyAliceLabelX, EncryptedData2WithX)
	//require.Nil(t, r)
	//require.Equal(t, data2, testDecryptFragsData2LabelX)
	//
	//testDecryptFragsData1LabelY, r := DecryptFragmentsWithRecover(cxt, capsule1Y, cFragsY1Y, privKeyBob, pubKeyAliceLabelY, EncryptedData1WithY)
	//require.Nil(t, r)
	//require.Equal(t, data1, testDecryptFragsData1LabelY)
	//
	//testDecryptFragsData2LabelY, r := DecryptFragmentsWithRecover(cxt, capsule2Y, cFragsY2Y, privKeyBob, pubKeyAliceLabelY, EncryptedData2WithY)
	//require.Nil(t, r)
	//require.Equal(t, data2, testDecryptFragsData2LabelY)
	//
	//// fail cases
	//d, r := DecryptFragmentsWithRecover(cxt, capsule2X, cFragsX1X, privKeyBob, pubKeyAliceLabelX, EncryptedData1WithX)
	//require.Equal(t, r, "Failed decapulation check")
	//require.Nil(t, d)
	//
	//d, r = DecryptFragmentsWithRecover(cxt, capsule2X, cFragsX1X, privKeyBob, pubKeyAliceLabelY, EncryptedData2WithX)
	//require.Equal(t, r, "Failed decapulation check")
	//require.Nil(t, d)
	//
	//d, r = DecryptFragmentsWithRecover(cxt, capsule1X, cFragsX1X, privKeyBob, pubKeyAliceLabelY, EncryptedData1WithX)
	//require.Equal(t, r, "Failed decapulation check")
	//require.Nil(t, d)
	//
	//// fail, bad cases
	//d, r = DecryptFragmentsWithRecover(cxt, capsule1Y, cFragsX1Y, privKeyBob, pubKeyAliceLabelY, EncryptedData1WithY)
	//require.Equal(t, r, "Failed decapulation check")
	//require.Nil(t, d)
	//
	//d, r = DecryptFragmentsWithRecover(cxt, capsule1Y, cFragsX1Y, privKeyBob, pubKeyAliceLabelX, EncryptedData1WithY)
	//require.Equal(t, r, "Failed DEM decryption")
	//require.Nil(t, d)
	//
	//d, r = DecryptFragmentsWithRecover(cxt, capsule2Y, cFragsX2Y, privKeyBob, pubKeyAliceLabelY, EncryptedData2WithY)
	//require.Equal(t, r, "Failed decapulation check")
	//require.Nil(t, d)
	//
	//d, r = DecryptFragmentsWithRecover(cxt, capsule2Y, cFragsX2Y, privKeyBob, pubKeyAliceLabelX, EncryptedData2WithY)
	//require.Equal(t, r, "Failed DEM decryption")
	//require.Nil(t, d)
	//
	//d, r = DecryptFragmentsWithRecover(cxt, capsule1X, cFragsY1X, privKeyBob, pubKeyAliceLabelY, EncryptedData1WithY)
	//require.Equal(t, r, "Failed DEM decryption")
	//require.Nil(t, d)
	//
	//d, r = DecryptFragmentsWithRecover(cxt, capsule1X, cFragsY1X, privKeyBob, pubKeyAliceLabelX, EncryptedData1WithY)
	//require.Equal(t, r, "Failed decapulation check")
	//require.Nil(t, d)
	//
	//d, r = DecryptFragmentsWithRecover(cxt, capsule2X, cFragsY2X, privKeyBob, pubKeyAliceLabelY, EncryptedData2WithX)
	//require.Equal(t, r, "Failed DEM decryption")
	//require.Nil(t, d)
	//
	//d, r = DecryptFragmentsWithRecover(cxt, capsule2X, cFragsY2X, privKeyBob, pubKeyAliceLabelX, EncryptedData2WithX)
	//require.Equal(t, r, "Failed decapulation check")
	//require.Nil(t, d)

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
//	//ctx := MakeDefaultContext()
//
//	//privKeyAlice := GenPrivateKey(ctx)
//	//pubKeyAlice := privKeyAlice.GetPublicKey(ctx)
//
//	//privKeyBob := GenPrivateKey(ctx)
//	//pubKeyBob := privKeyBob.GetPublicKey(ctx)
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
//	//cipherText, capsule := Encrypt(ctx, pubKeyAlice, symKey)
//	//testDecrypt := DecryptDirect(ctx, capsule, privKeyAlice, cipherText)
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
//	//kFrags := SplitReKey(ctx, privKeyAlice, pubKeyBob, threshold, 20)
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
//	//testDecryptFrags := DecryptFragments(ctx, capsule, cFrags, privKeyBob, pubKeyAlice, cipherText)
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