// +build linux

package openpgp

import (
	"fmt"
	"testing"
)

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
	}
	var keyring KeyRing
	keyring = kring
	keys := keyring.DecryptionKeys()
	fmt.Println("private Keys:", len(keys))
	fmt.Println("List private Key")
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
