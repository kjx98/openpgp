// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// +build linux

package openpgp

import (
	"os"

	"github.com/kjx98/openpgp/errors"
	"github.com/kjx98/openpgp/packet"
)

// An EntityList contains one or more Entities.
type EntityMap map[uint64][]Key

var keyMaps EntityMap = EntityMap{}
var privKeys []Key = []Key{}

func GetKeyMaps() (keyring EntityMap) {
	return keyMaps
}

func UnlockPrivate(kId uint64, passPhrase string) (uint64, error) {
	if keys, ok := keyMaps[kId]; !ok {
		return 0, errors.ErrKeyIncorrect
	} else {
		for _, key := range keys {
			if key.PrivateKey != nil {
				if !key.PrivateKey.Encrypted {
					return kId, nil
				}
				if err := key.PrivateKey.Decrypt([]byte(passPhrase)); err != nil {
					return 0, err
				}
				return kId, nil
			}
		}
	}
	return 0, errors.InvalidArgumentError("only Public key")
}

func upsetMap(kd Key) {
	var keys []Key
	kId := kd.PublicKey.KeyId
	if ks, ok := keyMaps[kId]; ok {
		keys = ks
	}
	for idx, kk := range keys {
		if kk.Entity == kd.Entity && kk.PublicKey.KeyId == kId {
			if kd.PrivateKey != nil {
				keys[idx] = kd
			}
			return
		}
	}
	keys = append(keys, kd)
	keyMaps[kId] = keys
}

func getKeyRing(ringName string, bArmor bool) (EntityList, error) {
	if ringName == "" {
		ringName = "pubring.gpg"
	}
	if ringName[0] != '/' && ringName[:2] != "./" {
		homeDir := os.Getenv("HOME")
		ringName = homeDir + "/.gnupg/" + ringName
	}
	if ff, err := os.Open(ringName); err != nil {
		return nil, err
	} else {
		defer ff.Close()
		if bArmor {
			return ReadArmoredKeyRing(ff)
		}
		return ReadKeyRing(ff)
	}
}

func init() {
	if kr, err := getKeyRing("", false); err == nil {
		mapAddKeyRing(kr)
	}
	if kr, err := getKeyRing("./expring.asc", true); err == nil {
		mapAddKeyRing(kr)
	}
}

func mapAddKeyRing(el EntityList) {
	for _, e := range el {
		var selfSig *packet.Signature
		for _, ident := range e.Identities {
			if selfSig == nil {
				selfSig = ident.SelfSignature
			} else if ident.SelfSignature.IsPrimaryId != nil && *ident.SelfSignature.IsPrimaryId {
				selfSig = ident.SelfSignature
				break
			}
		}
		upsetMap(Key{e, e.PrimaryKey, e.PrivateKey, selfSig})
		id := e.PrimaryKey.KeyId

		for _, subKey := range e.Subkeys {
			if subKey.PublicKey.KeyId != id {
				upsetMap(Key{e, subKey.PublicKey, subKey.PrivateKey, subKey.Sig})
			}
			if subKey.PrivateKey != nil && (!subKey.Sig.FlagsValid || subKey.Sig.FlagEncryptStorage || subKey.Sig.FlagEncryptCommunications) {
				privKeys = append(privKeys, Key{e, subKey.PublicKey, subKey.PrivateKey, subKey.Sig})
			}
		}
	}
	return
}

// KeysById returns the set of keys that have the given key id.
func (el EntityMap) KeysById(id uint64) (keys []Key) {
	if k, ok := keyMaps[id]; ok {
		keys = k
	}
	return
}

// KeysByIdAndUsage returns the set of keys with the given id that also meet
// the key usage given by requiredUsage.  The requiredUsage is expressed as
// the bitwise-OR of packet.KeyFlag* values.
func (el EntityMap) KeysByIdUsage(id uint64, requiredUsage byte) (keys []Key) {
	for _, key := range el.KeysById(id) {
		if len(key.Entity.Revocations) > 0 {
			continue
		}

		if key.SelfSignature.RevocationReason != nil {
			continue
		}

		if key.SelfSignature.FlagsValid && requiredUsage != 0 {
			var usage byte
			if key.SelfSignature.FlagCertify {
				usage |= packet.KeyFlagCertify
			}
			if key.SelfSignature.FlagSign {
				usage |= packet.KeyFlagSign
			}
			if key.SelfSignature.FlagEncryptCommunications {
				usage |= packet.KeyFlagEncryptCommunications
			}
			if key.SelfSignature.FlagEncryptStorage {
				usage |= packet.KeyFlagEncryptStorage
			}
			if usage&requiredUsage != requiredUsage {
				continue
			}
		}

		keys = append(keys, key)
	}
	return
}

// DecryptionKeys returns all private keys that are valid for decryption.
func (el EntityMap) DecryptionKeys() (keys []Key) {
	return privKeys
}
