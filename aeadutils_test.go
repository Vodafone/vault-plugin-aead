package aeadplugin

import (
	"bytes"
	"log"
	"reflect"
	"strings"
	"testing"

	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
)

func TestAeadUtils(t *testing.T) {
	t.Run("test aead", func(t *testing.T) {
		// t.Parallel()

		rawKeyset := `{"primaryKeyId":1416257722,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiBa0wZ4ACjtW137qTVSY2ofQBCffdzkzhNkktlMtDFazA==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1416257722,"outputPrefixType":"TINK"}]}`
		// jsonKeyset := `{
		// 	"primaryKeyId": 1416257722,
		// 	"key": [
		// 	  {
		// 		"keyData": {
		// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
		// 		  "value": "GiBa0wZ4ACjtW137qTVSY2ofQBCffdzkzhNkktlMtDFazA==",
		// 		  "keyMaterialType": "SYMMETRIC"
		// 		},
		// 		"status": "ENABLED",
		// 		"keyId": 1416257722,
		// 		"outputPrefixType": "TINK"
		// 	  }
		// 	]
		//   }`

		// create an aead keyhandle from the provided json as string
		kh, a, err := CreateInsecureHandleAndAead(rawKeyset)
		if err != nil {
			log.Fatal(err)
		}

		// set up some data
		msg := []byte("hello")
		aad := []byte("world")

		//  encrypt the data
		ct1, err := a.Encrypt(msg, aad)
		if err != nil {
			log.Fatal(err)
		}

		//  encrypt the data (again) - expect a different value
		ct2, err := a.Encrypt(msg, aad)
		if err != nil {
			log.Fatal(err)
		}

		// do the 2 decryptions match - they should not
		if bytes.Equal(ct1, ct2) {
			t.Error("cipher texts are not equal")
		}

		// decrypt the encrypted data
		pt1, err := a.Decrypt(ct1, aad)
		if err != nil {
			log.Fatal(err)
		}

		// does the decrypted data match the original data
		if string(pt1) != string(msg) {
			t.Errorf("expected %s got %s", msg, pt1)
		}

		// decrypt the 2nd encrypted data
		pt2, err := a.Decrypt(ct2, aad)
		if err != nil {
			log.Fatal(err)
		}

		// does the decrypted data match the original data
		if string(pt2) != string(msg) {
			t.Errorf("expected %s got %s", msg, pt2)
		}

		// get the key from the handle
		str, err := ExtractInsecureKeySetFromKeyhandle(kh)
		if err != nil {
			log.Fatal(err)
		}

		// check the key has the keyId and primaryKeyId we expect
		if !strings.Contains(str, `"keyId":1416257722`) {
			t.Errorf("written keyset %s does not contain a key with keyId 1416257722", str)
		}
		if !strings.Contains(str, "\"primaryKeyId\":1416257722") {
			t.Errorf("written keyset %s does not contain have primaryKeyId 1416257722", str)
		}

	})
	t.Run("test daead", func(t *testing.T) {
		// t.Parallel()
		rawKeyset := `{"primaryKeyId":42267057,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkDAEgACCd1/yruZMuI49Eig5Glb5koi0DXgx1mXVALYJWNRn5wYuQR46ggNuMhFfhrJCsddVp/Q7Pot2hvHoaQS","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":42267057,"outputPrefixType":"TINK"}]}`
		// jsonKeyset := `{
		// 	"primaryKeyId": 42267057,
		// 	"key": [
		// 	  {
		// 		"keyData": {
		// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesSivKey",
		// 		  "value": "EkDAEgACCd1/yruZMuI49Eig5Glb5koi0DXgx1mXVALYJWNRn5wYuQR46ggNuMhFfhrJCsddVp/Q7Pot2hvHoaQS",
		// 		  "keyMaterialType": "SYMMETRIC"
		// 		},
		// 		"status": "ENABLED",
		// 		"keyId": 42267057,
		// 		"outputPrefixType": "TINK"
		// 	  }
		// 	]
		//   }`

		// create a determinstic keyhandle from the provided json as string
		kh, d, err := CreateInsecureHandleAndDeterministicAead(rawKeyset)
		if err != nil {
			log.Fatal(err)
		}

		// set up some data
		msg := []byte("hello")
		aad := []byte("world")

		// determinstically encrypt the data
		ct1, err := d.EncryptDeterministically(msg, aad)
		if err != nil {
			log.Fatal(err)
		}

		// determinstically encrypt the data again
		ct2, err := d.EncryptDeterministically([]byte(msg), []byte(aad))
		if err != nil {
			t.Error(err)
		}

		// do the 2 decryptions match (determinstic)
		if !bytes.Equal(ct1, ct2) {
			t.Error("cipher texts are not equal")
		}

		// determinstically decrypt the encrypted data
		pt, err := d.DecryptDeterministically(ct1, aad)
		if err != nil {
			log.Fatal(err)
		}

		// does the decrypted data match the original data
		if string(pt) != string(msg) {
			t.Errorf("After decryption expected %s got %s", msg, pt)
		}

		// get the key from the handle
		str, err := ExtractInsecureKeySetFromKeyhandle(kh)
		if err != nil {
			log.Fatal(err)
		}

		// check the key has the keyId and primaryKeyId we expect
		if !strings.Contains(str, `"keyId":42267057`) {
			t.Errorf("written keyset %s does not contain a key with keyId :42267057", str)
		}
		if !strings.Contains(str, "\"primaryKeyId\":42267057") {
			t.Errorf("written keyset %s does not contain have primaryKeyId :42267057", str)
		}

	})

	t.Run("create new daead", func(t *testing.T) {
		// t.Parallel()

		_, d, err := CreateNewDeterministicAead()
		if err != nil {
			log.Fatal(err)
		}

		// set up some data
		msg := "this data needs to be encrypted"
		ad := "associated data"

		// determinstically encrypt the data
		ct1, err := d.EncryptDeterministically([]byte(msg), []byte(ad))
		if err != nil {
			t.Error(err)
		}

		// determinstically encrypt the data again
		ct2, err := d.EncryptDeterministically([]byte(msg), []byte(ad))
		if err != nil {
			t.Error(err)
		}

		// do the 2 decryptions match (determinstic)
		if !bytes.Equal(ct1, ct2) {
			t.Error("cipher texts are not equal")
		}

		// decrypt the deterministically encrypted data
		pt, err := d.DecryptDeterministically(ct1, []byte(ad))
		if err != nil {
			t.Error(err)
		}

		// does the decrypted data match the original data
		if string(pt) != msg {
			t.Errorf("After decryption expected %s got %s", msg, pt)
		}

	})

	t.Run("create new aead", func(t *testing.T) {
		// t.Parallel()

		_, a, err := CreateNewAead()
		if err != nil {
			log.Fatal(err)
		}

		// set up some data
		msg := "this data needs to be encrypted"
		aad := "associated data"

		// encrypt the data
		ct, err := a.Encrypt([]byte(msg), []byte(aad))
		if err != nil {
			log.Fatal(err)
		}

		// decrypt the encrypted data
		pt, err := a.Decrypt(ct, []byte(aad))
		if err != nil {
			log.Fatal(err)
		}

		// does the decrypted data match the original data
		if string(pt) != msg {
			t.Errorf("After decryption expected %s got %s", msg, pt)
		}
	})

	t.Run("test map pivot", func(t *testing.T) {
		// t.Parallel()

		/*
			set up a map that looks like this:
			length=3	map[row1:map[col1:value01 col2:value02] row2:map[col1:value21 col2:value22] row3:map[col1:value31 col2:value32 col3:value33 col4:value34]]
		*/

		origMap := make(map[string]map[string]string)
		origInnerMap1 := make(map[string]string)
		origInnerMap1["col1"] = "value01"
		origInnerMap1["col2"] = "value02"
		origMap["row1"] = origInnerMap1

		origInnerMap2 := make(map[string]string)
		origInnerMap2["col1"] = "value21"
		origInnerMap2["col2"] = "value22"
		origMap["row2"] = origInnerMap2

		origInnerMap3 := make(map[string]string)
		origInnerMap3["col1"] = "value31"
		origInnerMap3["col2"] = "value32"
		origInnerMap3["col3"] = "value33"
		origInnerMap3["col4"] = "value34"
		origMap["row3"] = origInnerMap3

		/*
			set up a target (pivoted) map that looks like this:
			length=4	map[col1:map[row1:value01 row2:value21 row3:value31] col2:map[row1:value02 row2:value22 row3:value32] col3:map[row3:value33] col4:map[row3:value34]]
		*/

		targetMap := make(map[string]map[string]string)
		targetInnerMap1 := make(map[string]string)
		targetInnerMap1["row1"] = "value01"
		targetInnerMap1["row2"] = "value21"
		targetInnerMap1["row3"] = "value31"

		targetMap["col1"] = targetInnerMap1

		targetInnerMap2 := make(map[string]string)
		targetInnerMap2["row1"] = "value02"
		targetInnerMap2["row2"] = "value22"
		targetInnerMap2["row3"] = "value32"
		targetMap["col2"] = targetInnerMap2

		targetInnerMap3 := make(map[string]string)
		targetInnerMap3["row3"] = "value33"
		targetMap["col3"] = targetInnerMap3

		targetInnerMap4 := make(map[string]string)
		targetInnerMap4["row3"] = "value34"
		targetMap["col4"] = targetInnerMap4

		actualMap := make(map[string]map[string]string)
		PivotMap(origMap, actualMap)

		if len(actualMap) != 4 {
			t.Errorf("actual map expected length=4 actual=%v", len(actualMap))
		}
		if !reflect.DeepEqual(targetMap, actualMap) {
			t.Errorf("maps are not the same \nexpected=%v \nactual=%v", targetMap, actualMap)
		}

		// and back again
		actualMap2 := make(map[string]map[string]string)
		PivotMap(actualMap, actualMap2)

		if len(actualMap2) != 3 {
			t.Errorf("2 actual map expected length=4 actual=%v", len(actualMap2))
		}
		if !reflect.DeepEqual(origMap, actualMap2) {
			t.Errorf("2 maps are not the same \nexpected=%v \nactual=%v", origMap, actualMap2)
		}

		// and back again
		actualMap3 := make(map[string]map[string]string)
		PivotMap(targetMap, actualMap3)

		if len(actualMap3) != 3 {
			t.Errorf("3 actual map expected length=4 actual=%v", len(actualMap3))
		}
		if !reflect.DeepEqual(origMap, actualMap3) {
			t.Errorf("3 maps are not the same \nexpected=%v \nactual=%v", origMap, actualMap3)
		}

	})

	t.Run("test map pivot interface{}", func(t *testing.T) {
		// t.Parallel()

		/*
			set up a map that looks like this:
			length=3	map[row1:map[col1:value01 col2:value02] row2:map[col1:value21 col2:value22] row3:map[col1:value31 col2:value32 col3:value33 col4:value34]]
		*/

		origMap := make(map[string]interface{})
		origInnerMap1 := make(map[string]interface{})
		origInnerMap1["col1"] = "value01"
		origInnerMap1["col2"] = "value02"
		origMap["row1"] = origInnerMap1

		origInnerMap2 := make(map[string]interface{})
		origInnerMap2["col1"] = "value21"
		origInnerMap2["col2"] = "value22"
		origMap["row2"] = origInnerMap2

		origInnerMap3 := make(map[string]interface{})
		origInnerMap3["col1"] = "value31"
		origInnerMap3["col2"] = "value32"
		origInnerMap3["col3"] = "value33"
		origInnerMap3["col4"] = "value34"
		origMap["row3"] = origInnerMap3

		/*
			set up a target (pivoted) map that looks like this:
			length=4	map[col1:map[row1:value01 row2:value21 row3:value31] col2:map[row1:value02 row2:value22 row3:value32] col3:map[row3:value33] col4:map[row3:value34]]
		*/

		targetMap := make(map[string]interface{})
		targetInnerMap1 := make(map[string]interface{})
		targetInnerMap1["row1"] = "value01"
		targetInnerMap1["row2"] = "value21"
		targetInnerMap1["row3"] = "value31"

		targetMap["col1"] = targetInnerMap1

		targetInnerMap2 := make(map[string]interface{})
		targetInnerMap2["row1"] = "value02"
		targetInnerMap2["row2"] = "value22"
		targetInnerMap2["row3"] = "value32"
		targetMap["col2"] = targetInnerMap2

		targetInnerMap3 := make(map[string]interface{})
		targetInnerMap3["row3"] = "value33"
		targetMap["col3"] = targetInnerMap3

		targetInnerMap4 := make(map[string]interface{})
		targetInnerMap4["row3"] = "value34"
		targetMap["col4"] = targetInnerMap4

		actualMap := make(map[string]interface{})
		PivotMapInt(origMap, actualMap)

		if len(actualMap) != 4 {
			t.Errorf("actual map expected length=4 actual=%v", len(actualMap))
		}
		if !reflect.DeepEqual(targetMap, actualMap) {
			t.Errorf("maps are not the same \nexpected=%v \nactual=%v", targetMap, actualMap)
		}

		// and back again
		actualMap2 := make(map[string]interface{})
		PivotMapInt(actualMap, actualMap2)

		if len(actualMap2) != 3 {
			t.Errorf("2 actual map expected length=4 actual=%v", len(actualMap2))
		}
		if !reflect.DeepEqual(origMap, actualMap2) {
			t.Errorf("2 maps are not the same \nexpected=%v \nactual=%v", origMap, actualMap2)
		}

		// and back again
		actualMap3 := make(map[string]interface{})
		PivotMapInt(targetMap, actualMap3)

		if len(actualMap3) != 3 {
			t.Errorf("3 actual map expected length=4 actual=%v", len(actualMap3))
		}
		if !reflect.DeepEqual(origMap, actualMap3) {
			t.Errorf("3 maps are not the same \nexpected=%v \nactual=%v", origMap, actualMap3)
		}

	})

	t.Run("test update status", func(t *testing.T) {
		// t.Parallel()
		rawKeyset := `{"primaryKeyId":42267057,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkDAEgACCd1/yruZMuI49Eig5Glb5koi0DXgx1mXVALYJWNRn5wYuQR46ggNuMhFfhrJCsddVp/Q7Pot2hvHoaQS","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":42267057,"outputPrefixType":"TINK"}]}`
		// jsonKeyset := `{
		// 	"primaryKeyId": 42267057,
		// 	"key": [
		// 	  {
		// 		"keyData": {
		// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesSivKey",
		// 		  "value": "EkDAEgACCd1/yruZMuI49Eig5Glb5koi0DXgx1mXVALYJWNRn5wYuQR46ggNuMhFfhrJCsddVp/Q7Pot2hvHoaQS",
		// 		  "keyMaterialType": "SYMMETRIC"
		// 		},
		// 		"status": "ENABLED",
		// 		"keyId": 42267057,
		// 		"outputPrefixType": "TINK"
		// 	  }
		// 	]
		//   }`

		// create a determinstic keyhandle from the provided json as string
		kh, _, err := CreateInsecureHandleAndDeterministicAead(rawKeyset)
		if err != nil {
			log.Fatal(err)
		}

		newkh, err := UpdateKeyStatus(kh, "42267057", "DISABLED")

		buf := new(bytes.Buffer)
		jsonWriter := keyset.NewJSONWriter(buf)

		insecurecleartextkeyset.Write(newkh, jsonWriter)

		// unmarshall the keyset
		str := buf.String()
		// fmt.Printf("STATUS CHANGE=%s", str)

		if !strings.Contains(str, "DISABLED") && strings.Contains(str, "ENABLED") {
			t.Errorf("key was not disabled %s", str)
		}

	})

	t.Run("test update material", func(t *testing.T) {
		// t.Parallel()
		rawKeyset := `{"primaryKeyId":3987026049,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiB5m/rHV+xmMiRngaWWi6zel8IjlOPCdEpGnEsb8RfrMQ==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1456486908,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiCRExtHflcWVUbmk0mwB5TzqSGc3GVMu6Hk+HbL4oH61A==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3987026049,"outputPrefixType":"TINK"}]}`
		// {
		// 	"primaryKeyId": 3987026049,
		// 	"key": [
		// 	  {
		// 		"keyData": {
		// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
		// 		  "value": "GiB5m/rHV+xmMiRngaWWi6zel8IjlOPCdEpGnEsb8RfrMQ==",
		// 		  "keyMaterialType": "SYMMETRIC"
		// 		},
		// 		"status": "ENABLED",
		// 		"keyId": 1456486908,
		// 		"outputPrefixType": "TINK"
		// 	  },
		// 	  {
		// 		"keyData": {
		// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
		// 		  "value": "GiCRExtHflcWVUbmk0mwB5TzqSGc3GVMu6Hk+HbL4oH61A==",
		// 		  "keyMaterialType": "SYMMETRIC"
		// 		},
		// 		"status": "ENABLED",
		// 		"keyId": 3987026049,
		// 		"outputPrefixType": "TINK"
		// 	  }
		// 	]
		//   }

		// create a determinstic keyhandle from the provided json as string
		kh, _, err := CreateInsecureHandleAndAead(rawKeyset)

		if err != nil {
			log.Fatal(err)
		}

		newkh, err := UpdateKeyMaterial(kh, "1456486908", "GiApAwR1VAPVxpIrRiBGw2RziWx04nzHVDYu1ocipSDCvQ==")

		buf := new(bytes.Buffer)
		jsonWriter := keyset.NewJSONWriter(buf)

		insecurecleartextkeyset.Write(newkh, jsonWriter)

		// unmarshall the keyset
		str := buf.String()
		// fmt.Printf("MATERIAL CHANGE=%s", str)

		if !strings.Contains(str, "GiApAwR1VAPVxpIrRiBGw2RziWx04nzHVDYu1ocipSDCvQ==") {
			t.Errorf("key material was not changed %s", str)
		}

	})

	t.Run("test update key id", func(t *testing.T) {
		// t.Parallel()
		rawKeyset := `{"primaryKeyId":3987026049,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiB5m/rHV+xmMiRngaWWi6zel8IjlOPCdEpGnEsb8RfrMQ==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1456486908,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiCRExtHflcWVUbmk0mwB5TzqSGc3GVMu6Hk+HbL4oH61A==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3987026049,"outputPrefixType":"TINK"}]}`
		// {
		// 	"primaryKeyId": 3987026049,
		// 	"key": [
		// 	  {
		// 		"keyData": {
		// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
		// 		  "value": "GiB5m/rHV+xmMiRngaWWi6zel8IjlOPCdEpGnEsb8RfrMQ==",
		// 		  "keyMaterialType": "SYMMETRIC"
		// 		},
		// 		"status": "ENABLED",
		// 		"keyId": 1456486908,
		// 		"outputPrefixType": "TINK"
		// 	  },
		// 	  {
		// 		"keyData": {
		// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
		// 		  "value": "GiCRExtHflcWVUbmk0mwB5TzqSGc3GVMu6Hk+HbL4oH61A==",
		// 		  "keyMaterialType": "SYMMETRIC"
		// 		},
		// 		"status": "ENABLED",
		// 		"keyId": 3987026049,
		// 		"outputPrefixType": "TINK"
		// 	  }
		// 	]
		//   }

		// create a determinstic keyhandle from the provided json as string
		kh, _, err := CreateInsecureHandleAndAead(rawKeyset)

		if err != nil {
			log.Fatal(err)
		}

		// update the keyid and primary id to a new number
		newkh, err := UpdateKeyID(kh, "3987026049", "3987026050")

		buf := new(bytes.Buffer)
		jsonWriter := keyset.NewJSONWriter(buf)

		insecurecleartextkeyset.Write(newkh, jsonWriter)

		// unmarshall the keyset
		str := buf.String()
		// fmt.Printf("KEYID CHANGE=%s", str)

		if !strings.Contains(str, "primaryKeyId\":3987026050") && !strings.Contains(str, "keyId\":3987026050") {
			t.Errorf("primary key ID was not changed %s", str)
		}

		if !strings.Contains(str, "keyId\":3987026050") {
			t.Errorf("key ID was not changed %s", str)
		}
	})

	t.Run("test update primary key id", func(t *testing.T) {
		// t.Parallel()
		rawKeyset := `{"primaryKeyId":3987026049,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiB5m/rHV+xmMiRngaWWi6zel8IjlOPCdEpGnEsb8RfrMQ==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1456486908,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiCRExtHflcWVUbmk0mwB5TzqSGc3GVMu6Hk+HbL4oH61A==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3987026049,"outputPrefixType":"TINK"}]}`
		// {
		// 	"primaryKeyId": 3987026049,
		// 	"key": [
		// 	  {
		// 		"keyData": {
		// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
		// 		  "value": "GiB5m/rHV+xmMiRngaWWi6zel8IjlOPCdEpGnEsb8RfrMQ==",
		// 		  "keyMaterialType": "SYMMETRIC"
		// 		},
		// 		"status": "ENABLED",
		// 		"keyId": 1456486908,
		// 		"outputPrefixType": "TINK"
		// 	  },
		// 	  {
		// 		"keyData": {
		// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
		// 		  "value": "GiCRExtHflcWVUbmk0mwB5TzqSGc3GVMu6Hk+HbL4oH61A==",
		// 		  "keyMaterialType": "SYMMETRIC"
		// 		},
		// 		"status": "ENABLED",
		// 		"keyId": 3987026049,
		// 		"outputPrefixType": "TINK"
		// 	  }
		// 	]
		//   }

		// create a determinstic keyhandle from the provided json as string
		kh, _, err := CreateInsecureHandleAndAead(rawKeyset)

		if err != nil {
			log.Fatal(err)
		}

		// update the keyid and primary id to a new number
		newkh, err := UpdatePrimaryKeyID(kh, "1456486908")

		buf := new(bytes.Buffer)
		jsonWriter := keyset.NewJSONWriter(buf)

		insecurecleartextkeyset.Write(newkh, jsonWriter)

		// unmarshall the keyset
		str := buf.String()
		// fmt.Printf("KEYID CHANGE=%s", str)

		if !strings.Contains(str, "primaryKeyId\":1456486908") {
			t.Errorf("primary key ID was not changed %s", str)
		}

	})

	t.Run("test getEncryptionKey", func(t *testing.T){
		rawKeyset := `{"primaryKeyId":3987026049,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiB5m/rHV+xmMiRngaWWi6zel8IjlOPCdEpGnEsb8RfrMQ==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1456486908,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiCRExtHflcWVUbmk0mwB5TzqSGc3GVMu6Hk+HbL4oH61A==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3987026049,"outputPrefixType":"TINK"}]}`

		key, ok := getEncryptionKey("test")
		if ok {
			t.Errorf("shouldn't find the key as it was not set: %s", key.(string))
		}
		AEAD_CONFIG.Set("test", "foo")
		key, ok = getEncryptionKey("test")
		if ok {
			t.Errorf("shouldn't find the value \"foo\", as there is no key set. got: %s", key.(string))
		}

		AEAD_CONFIG.Set("test", rawKeyset)
		key, ok = getEncryptionKey("test")
		if !ok {
			t.Errorf("should find the keyset. got: %s", key.(string))
		}


		AEAD_CONFIG.Set("test", "cat1")
		AEAD_CONFIG.Set("cat1", rawKeyset)

		key, ok = getEncryptionKey("test")
		if !ok {
			t.Errorf("should find the keyset. got: %s", key.(string))
		}

		AEAD_CONFIG.Set("test", "cat1")
		AEAD_CONFIG.Set("cat1", "cat2")
		AEAD_CONFIG.Set("cat2", "cat3")
		AEAD_CONFIG.Set("cat3", "cat4")
		AEAD_CONFIG.Set("cat4", "cat5")
		AEAD_CONFIG.Set("cat5", "cat6")
		AEAD_CONFIG.Set("cat6", "cat7")
		AEAD_CONFIG.Set("cat7", rawKeyset)

		key, ok = getEncryptionKey("test")
		if ok {
			t.Errorf("shouldn't find the keyset. got: %s", key.(string))
		}

		key, ok = getEncryptionKey("test", 10)
		if !ok {
			t.Errorf("should find the keyset. got: %s", key.(string))
		}

	})
}
