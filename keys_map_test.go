// +build linux

package openpgp

import (
	"bytes"
	"fmt"
	"github.com/kjx98/openpgp/armor"
	"io/ioutil"
	"strings"
	"testing"
)

func dumpKeys(keys []Key) {
	for _, ee := range keys {
		fmt.Printf("PUB: %X\n", ee.PublicKey.KeyId)
		for idN, _ := range ee.Entity.Identities {
			fmt.Println("ID:", idN)
		}
		if ee.PrivateKey != nil {
			fmt.Println("Private Encrypted:", ee.PrivateKey.Encrypted)
		}
	}
}

var eckeyId uint64 = 0x11E6F3B8AFCB2F76
var edkeyId uint64 = 0xae9e177e5de31b10
var enText string = `
-----BEGIN PGP MESSAGE-----

hF4DEebzuK/LL3YSAQdA+d78a2wmBjKwaL7VPEy7MMXvbx/kIAR2d18Bs7SEuU4w
qvBPKYuYt29uuJVLoCV/HEIo9X3JqKDoNptArscj3PradwrlgetWX+lXFGUJIDZt
0n0BtOt5sWYgO/xyhJd4kQjvCyzCPtPwAuLXpaKE6XcIuXUmAsEmpXlP7uSIeEJ9
lkeFJgdPgNwzjSl/k/QYu6Sn1hXt9DD4/mQ4yStfUtkVDMMloMVupv17/Y8/vxAh
krSe229jmDAWFJmbXW/F77ZzPpbDbkc7sDrEK4yDqA==
=Xn0A
-----END PGP MESSAGE-----
`
var enSignText string = `
-----BEGIN PGP MESSAGE-----

hF4DEebzuK/LL3YSAQdANwxlYUDTIg42a+x0O+s8UhTvGfH00UsptHratRMqVT0w
xX4sQLg0Ttm44RcX1RbH25eTS6FqsVIXxMTmMY44A8uqlMmptzJEtu8/gcpR4hf5
0sBVAbnnURF/SV+SzI7P8NvBgxitahTWNu2qM0h7I7ulSMU+nNuxGr1UGEZ7wBCc
Yd1PAGQHl7KNXulgBQVEs9IGoH1PLil1dkoLQhdHCWpR2FlJX+7B0mqF2wNcok1E
R0ayNhZ398MGK5XhaQOhhmITNMa2nesXILdhHqwKKE6RuBAmoTNXPmW82oXJRXbj
l3/MZrIo6/uOnlMMgQN2IcmWqtSA2PrByFi1EC0pkl1gr2Z3KJ1VMfmJFU3LCqpt
wHm9Ee4PLoh0tbWGKC+7x6SapvfJIxSErzepI/GMiMqjjngreDt2bjam2X0an+OX
1uZ/9c7Jk7Lm/L9kzTme3ISD7Xqs9NTMSck73k/JN1YvqSQZPJHXDw==
=TEaV
-----END PGP MESSAGE-----
`
var signText string = `
-----BEGIN PGP MESSAGE-----

owNCWmg5MUFZJlNZbffW0AAAN3////rRvnPNMHwQRBKrFx2e0SDUQANzJQAKiJng
KguhsBkgAJIYgAAAAAAAAAAAAMhoGgGmmnqeiGEaNNA0GgBpoAAAANAAGhoaaAAG
g0I96QVITqWp1lhuHO8gMhhwkvwvMQAzC+iOhzATn/gGMJdW1yvyB1isHiQpedeG
yb3NjayqR9VZuGFBnG462jH1lHnafAgBAWh+TZ25OBi/b6LBHNu6qA+v5vLFjjfS
A+zSLlsYoBJPTuC/2EB6xBKLLFRmGIBDASDTgnRm538XckU4UJBt99bQ
=h2nW
-----END PGP MESSAGE-----
`

func TestGetKeyMaps(t *testing.T) {
	kring := GetKeyMaps()
	fmt.Println("keyMap size:", len(kring))
	fmt.Println("List keyMap")
	for _, keys := range kring {
		if len(keys) == 0 {
			continue
		}
		kk := keys[0]
		bitLen, _ := kk.PublicKey.BitLength()
		fmt.Printf("Entity %s(%d) PUB: %s\n", kk.PublicKey.PubKeyAlgo,
			bitLen, kk.PublicKey.KeyIdString())
		if kk.PrivateKey != nil {
			fmt.Println("\twith PrivateKey.")
		}
	}
	if len(kring) == 0 {
		t.Error("Empty keyring")
		return
	}
	var keyring KeyRing
	keyring = kring
	keys := keyring.DecryptionKeys()
	fmt.Println("private Keys:", len(keys))
	fmt.Println("List private Key")
	dumpKeys(keys)
	keys = keyring.KeysById(eckeyId)
	t.Logf("ECDH keys: %d", len(keys))
	dumpKeys(keys)
	keys = keyring.KeysById(edkeyId)
	t.Logf("EdDSA keys: %d", len(keys))
	dumpKeys(keys)
}

func TestReadEd25519Msg(t *testing.T) {
	kring := GetKeyMaps()
	t.Log("Test Decode Message")
	if _, err := UnlockPrivate(eckeyId, "testme"); err != nil {
		t.Error(err)
	}
	sig, err := armor.Decode(strings.NewReader(enText))
	if err != nil {
		t.Error(err)
		return
	}
	md, err := ReadMessage(sig.Body, kring, nil, nil)
	if err != nil {
		t.Error(err)
		return
	}
	contents, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Errorf("error reading UnverifiedBody: %s", err)
	}
	expected := "Hello World!\n"
	if string(contents) != expected {
		t.Errorf("bad UnverifiedBody got:%s want:%s", string(contents), expected)
	}
}

func TestReadEd25519SignedMsg(t *testing.T) {
	kring := GetKeyMaps()
	t.Log("Test Decode Signed Message")
	sig, err := armor.Decode(strings.NewReader(enSignText))
	if err != nil {
		t.Error(err)
		return
	}
	md, err := ReadMessage(sig.Body, kring, nil, nil)
	if err != nil {
		t.Error(err)
		return
	}
	if !md.IsSigned || md.SignedByKeyId != edkeyId || md.SignedBy == nil || !md.IsEncrypted || md.IsSymmetricallyEncrypted {
		t.Errorf("bad MessageDetails: %#v", md)
	}
	contents, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Errorf("error reading UnverifiedBody: %s", err)
	}
	expected := "Hello World!\n"
	if string(contents) != expected {
		t.Errorf("bad UnverifiedBody got:%s want:%s", string(contents), expected)
	}
	if md.Signature == nil {
		t.Error("failed to validate: no Signature")
	}
	if md.SignatureError != nil {
		t.Errorf("failed to validate: %s", md.SignatureError)
	}
}

func BenchmarkEncrypt25519(b *testing.B) {
	kring := GetKeyMaps()
	var message [32768]byte
	copy(message[:], []byte("Hello World!\n"))
	for i := 0; i < b.N; i++ {
		buf := new(bytes.Buffer)
		var to *Entity
		to = kring[eckeyId][0].Entity
		tos := []*Entity{to}
		w, err := Encrypt(buf, tos, nil, nil, nil)
		if err != nil {
			return
		}
		_, err = w.Write(message[:])
		err = w.Close()
	}
}

func BenchmarkDecrypt25519(b *testing.B) {
	kring := GetKeyMaps()
	for i := 0; i < b.N; i++ {
		sig, err := armor.Decode(strings.NewReader(enText))
		if err != nil {
			return
		}
		md, err := ReadMessage(sig.Body, kring, nil, nil)
		if err != nil {
			return
		}
		_, err = ioutil.ReadAll(md.UnverifiedBody)
	}
}

func BenchmarkVerify25519(b *testing.B) {
	kring := GetKeyMaps()
	for i := 0; i < b.N; i++ {
		sig, err := armor.Decode(strings.NewReader(signText))
		if err != nil {
			return
		}
		md, err := ReadMessage(sig.Body, kring, nil, nil)
		if err != nil {
			return
		}
		_, err = ioutil.ReadAll(md.UnverifiedBody)
	}
}
