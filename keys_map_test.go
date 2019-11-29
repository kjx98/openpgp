// +build linux

package openpgp

import (
	"fmt"
	"github.com/kjx98/openpgp/armor"
	"github.com/kjx98/openpgp/errors"
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
			if ee.PrivateKey.Encrypted {
				// TODO: console get passphrase
				passphrase := "testme"
				if err := ee.PrivateKey.Decrypt([]byte(passphrase)); err == nil {
					fmt.Println("Passphrase ok")
				} else {
					fmt.Println("Invalid passphrase", err)
				}
			}
		}
	}
}

var eckeyId uint64 = 0x11E6F3B8AFCB2F76
var edkeyId uint64 = 0xf58f7e0a27b3228
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

hF4DEebzuK/LL3YSAQdAu6mXSOY2yfemj2bVWeCj+CDKc3pm02WSxSIDE1Ez8T0w
/JxVNolOfynq5BIu4Uvl/n43MIYnIUeyIVZrHa6tfku3bYQTBXbWIpaYomjbfQKo
0ukBBSyycvyQWgAICxqPmxWkSfCSAIAoZsGIuc8FfZoJAOd8qjF8WKIxl03YYYdz
jW88bVirfpyWR+xqndD+YbI1Oycxe+9nBDV4QbXuTYaOdOUjNFKavGGeVpHNNP0r
YJOVm9waVGNK5WcpzhQzbwwj4K6dXs2eUsZBQJvYzMEn+8TFpl1etwYG962aBaZH
iw19cTTrcXIEJY4eeVGzDkvv04vrEqs3BGD97l8JAEp79XsSG7RZF+D5r0Kz8X1/
G51J4M1t26ISoZ+qGg/iTf1iAxYB/Sat1Hln3HQywqi7MZ3bQXWYeb/wlRaVzee+
uIvOQdh50YpOg4WM3V9kxMq76wXXjpBqIw+rfQruWFv7fyG8wqTmxtkzZIGhW59q
kMV8DatVk6PNdZb7wdzPI8p1fvPTOyaMxOopTrgyMiyVsCRVFc9ph0+ZfpwpFW2/
HOMX5zJHG/TZCHTFfrs6R22fEhfj/Fr1dcKcmikWt4xd9MfZy55iz4OkMXZu/FCm
7lasRtdACuXaETi/Zpfkz7yvvXBi3mHMwYtvE9Pv/H9E6Pnkj8mfxWvVivvUFcHY
WQIXLJLPyrYg+xStDgwPv4JHKiDXAB9ZhB2TmLlNq5EeqvNDT/l5VUb9rr8vyObl
rU2gKOm23FyGO2+Skt9m80QN1timepD0mwdpRMQhW8Ou8iOvYh+SdWQanMfhaDIS
oa5fsBTRNVGVIUlk8bp+cEtLQiUVUA==
=7uiL
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
	prompt := func(keys []Key, symmetric bool) ([]byte, error) {
		if symmetric {
			t.Errorf("prompt: message was marked as symmetrically encrypted")
			return nil, errors.ErrKeyIncorrect
		}

		if len(keys) == 0 {
			t.Error("prompt: no keys requested")
			return nil, errors.ErrKeyIncorrect
		}

		err := keys[0].PrivateKey.Decrypt([]byte("passphrase"))
		if err != nil {
			t.Errorf("prompt: error decrypting key: %s", err)
			return nil, errors.ErrKeyIncorrect
		}

		return nil, nil
	}
	kring := GetKeyMaps()
	t.Log("Test Decode Signed Message")
	sig, err := armor.Decode(strings.NewReader(enSignText))
	if err != nil {
		t.Error(err)
		return
	}
	md, err := ReadMessage(sig.Body, kring, prompt, nil)
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
	if md.SignatureError != nil || md.Signature == nil {
		t.Errorf("failed to validate: %s", md.SignatureError)
	}
}
