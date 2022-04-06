package aeadplugin

import (
	"bytes"
	"fmt"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"

	hclog "github.com/hashicorp/go-hclog"
)

func CreateInsecureHandleAndAead(rawKeyset string) (*keyset.Handle, tink.AEAD, error) {
	r := keyset.NewJSONReader(bytes.NewBufferString(rawKeyset))

	kh, err := insecurecleartextkeyset.Read(r)

	if err != nil {
		hclog.L().Error("Failed to get the keyset:  %v", err)
	}
	a, err := aead.New(kh)
	if err != nil {
		hclog.L().Error("Failed to get the key:  %v", err)
	}
	return kh, a, nil
}

func CreateInsecureHandleAndDeterministicAead(rawKeyset string) (*keyset.Handle, tink.DeterministicAEAD, error) {
	r := keyset.NewJSONReader(bytes.NewBufferString(rawKeyset))

	kh, err := insecurecleartextkeyset.Read(r)

	if err != nil {
		hclog.L().Error("Failed to get the keyset:  %v", err)
	}
	d, err := daead.New(kh)
	if err != nil {
		hclog.L().Error("Failed to get the key:  %v", err)
	}
	return kh, d, nil
}

func ExtractInsecureKeySetFromKeyhandle(kh *keyset.Handle) (string, error) {
	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)

	err := insecurecleartextkeyset.Write(kh, w)

	if err != nil {
		hclog.L().Error("cannot write keyset:  %v", err)
		return "", nil
	}
	return buf.String(), nil
}

func CreateNewDeterministicAead() (*keyset.Handle, tink.DeterministicAEAD, error) {
	kh, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		hclog.L().Error("cannot create key handle:  %v", err)
	}

	d, err := daead.New(kh)
	if err != nil {
		hclog.L().Error("cannot get det aead:  %v", err)
	}
	return kh, d, nil
}

func CreateNewAead() (*keyset.Handle, tink.AEAD, error) {
	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		hclog.L().Error("cannot create new aead keyhandle:  %v", err)
		return nil, nil, err
	}

	a, err := aead.New(kh)
	if err != nil {
		hclog.L().Error("cannot create new aead key:  %v", err)
		return nil, nil, err
	}
	return kh, a, nil
}

func RotateKeys(kh *keyset.Handle, deterministic bool) {
	manager := keyset.NewManagerFromHandle(kh)
	if deterministic {
		manager.Rotate(daead.AESSIVKeyTemplate())
	} else {
		manager.Rotate(aead.AES256GCMKeyTemplate())
	}
}

func IsKeyDeterministic(kh *keyset.Handle) bool {
	// the alt to this is to convert the key info tom json and trawl through it
	// i hate this, but i don't see an alternative atm

	// also, it seems you cannot have a keyset that has both deterministic and non deterministic types
	deterministic := false

	// is the key AEAD
	_, err := aead.New(kh)
	if err != nil {
		// is the key DAEAD
		_, err := daead.New(kh)
		if err != nil {
			panic(err)
		} else {
			deterministic = true
		}
	}
	return deterministic
}

func PivotMap(originalMap map[string]map[string]string, newMap map[string]map[string]string) {
	for k, v := range originalMap {
		// fmt.Printf("\nk=%v v=%v", k, v)
		for ki, vi := range v {
			// fmt.Printf("\nki=%v vi=%v", ki, vi)
			newInnerMap, ok := newMap[ki]
			if ok {
				newInnerMap[k] = vi
				newMap[ki] = newInnerMap
			} else {
				newInnerMap := make(map[string]string)
				newInnerMap[k] = vi
				newMap[ki] = newInnerMap
			}
		}
	}
}

func PivotMapInt(mo map[string]interface{}, nmo map[string]interface{}) {
	for k, v := range mo {
		// fmt.Printf("\nk=%v v=%v", k, v)
		vm, ok := v.(map[string]interface{})
		if !ok {
			hclog.L().Error("cannot create new aead keyhandleouter assertion failed")
		}
		for ki, vi := range vm {
			// fmt.Printf("\nki=%v vi=%v", ki, vi)

			nmi, ok := nmo[ki]

			if ok {
				nmi2, ok2 := nmi.(map[string]interface{})
				if !ok2 {
					fmt.Printf("inner assertion failed")
				}
				nmi2[k] = vi
				nmo[ki] = nmi2
			} else {
				nmi2 := make(map[string]interface{})
				nmi2[k] = vi
				nmo[ki] = nmi2
			}
		}
	}
}
