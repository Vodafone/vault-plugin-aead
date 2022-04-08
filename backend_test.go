package aeadplugin

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	"log"
	"reflect"
	"strings"
	"testing"

	version "github.com/Vodafone/vault-plugin-aead/version"
	"github.com/hashicorp/vault/sdk/logical"
)

func testBackend(tb testing.TB) (*backend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal("20", err)
	}
	return b.(*backend), config.StorageView
}

func TestBackend(t *testing.T) {
	t.Run("test1 info read", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		resp := readInfo(b, storage, t)

		compareStrings(resp, "version", version.Version, t)

	})

	t.Run("test2 config write and read back", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		data := map[string]interface{}{
			"test2-hola":    "mundo",
			"test2-hello":   "world",
			"test2-bonjour": "le monde",
		}

		saveConfig(b, storage, data, false, t)

		resp := readConfig(b, storage, t)

		compareStrings(resp, "test2-hello", "world", t)

		compareStrings(resp, "test2-bonjour", "le monde", t)

		compareStrings(resp, "test2-hola", "mundo", t)

	})

	t.Run("test3 update the key set and make sure the last one is stored", func(t *testing.T) {
		// t.Parallel()

		storeKeyValue("test3-hello1", "world1", t)
		storeKeyValue("test3-hello2", "world2", t)
		storeKeyValue("test3-hello1", "world2", t)
	})

	t.Run("test4 deterministic encryption with supplied DetAEAD key", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		encryptionJsonKey := `{"primaryKeyId":42267057,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkDAEgACCd1/yruZMuI49Eig5Glb5koi0DXgx1mXVALYJWNRn5wYuQR46ggNuMhFfhrJCsddVp/Q7Pot2hvHoaQS","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":42267057,"outputPrefixType":"TINK"}]}`
		// set up some encryption keys to be used
		encryptionMap := map[string]interface{}{
			"test4-address": encryptionJsonKey,
			"test4-phone":   encryptionJsonKey,
		}

		// store the config
		saveConfig(b, storage, encryptionMap, false, t)

		// set some data to be encrypted using the keys
		data := map[string]interface{}{
			"test4-address": "my address",
			"test4-phone":   "my phone",
		}

		resp := encryptData(b, storage, data, t)

		// now we need to use the same key to encrypt the same data to get the expected value
		// create key from string
		_, d, err := CreateInsecureHandleAndDeterministicAead(encryptionJsonKey)
		if err != nil {
			log.Fatal(err)
		}

		// encrypt it
		aad := []byte("test4-address")
		msg := []byte("my address")
		ct, err := d.EncryptDeterministically([]byte(msg), aad)
		if err != nil {
			log.Fatal(err)
		}

		// set the response as the base64 encrypted data
		exp := b64.StdEncoding.EncodeToString(ct)

		act := fmt.Sprintf("%v", resp.Data["test4-address"]) // convert the cyphertext (=interface{}) received to a string
		if act == "" || act != exp {
			t.Errorf("expected %q to be %q", act, exp)
		}

	})

	t.Run("test5 deterministic encryption with dynamically generated DetAEAD key", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		// set some data to be encrypted using the keys
		data := map[string]interface{}{
			"test5-address2": "my address",
			"test5-phone2":   "my phone",
		}

		resp := encryptDataDetermisticallyAndCreateKey(b, storage, data, false, t)

		// retreive the encrypted data for field address
		actualEncryptedValue := fmt.Sprintf("%v", resp.Data["test5-address2"]) // convert the cyphertext (=interface{}) received to a string

		// now read the config
		configResp := readConfig(b, storage, t)

		// get the actual Json key used from teh config for address
		actualJSonKey := configResp.Data["test5-address2"].(string)

		// re-encrypt the data using the same key
		_, d, err := CreateInsecureHandleAndDeterministicAead(actualJSonKey)
		if err != nil {
			log.Fatal(err)
		}

		// encrypt it
		ct, err := d.EncryptDeterministically([]byte("my address"), []byte("test5-address2"))
		if err != nil {
			log.Fatal(err)
		}

		// expectedEncryptedValue := string(ct)
		// set the response as the base64 encrypted data
		expectedEncryptedValue := b64.StdEncoding.EncodeToString(ct)

		if expectedEncryptedValue != actualEncryptedValue {
			t.Errorf("expected %q to be %q", actualEncryptedValue, expectedEncryptedValue)
		}
	})

	t.Run("test6 non-deterministic encryption with dynamically generated AEAD key", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		// create a dynamic AEAD key for a field
		// set some data to be encrypted using the keys
		data := map[string]interface{}{
			"test6-address3": "my address",
		}

		encryptDataNonDetermisticallyAndCreateKey(b, storage, data, false, t)

		// encrypt the data
		resp := encryptData(b, storage, data, t)

		// get the actual Json key used from teh config for address
		encryptedData := resp.Data["test6-address3"].(string)

		if encryptedData == "my address" {
			t.Error("encrypted data is the same as original data")
		}

		// get the config
		configResp := readConfig(b, storage, t)

		// get the actual Json key used from teh config for address
		actualJSonKey := configResp.Data["test6-address3"].(string)

		if !strings.Contains(actualJSonKey, "AesGcmKey") {
			t.Error("key is not a AesGcmKey")
		}

	})

	t.Run("test7 non-deterministic encryption with supplied AEAD key", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

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

		configData := map[string]interface{}{
			"test7-address4": rawKeyset,
		}

		saveConfig(b, storage, configData, false, t)

		data := map[string]interface{}{
			"test7-address4": "my address",
		}

		// encrypt the data
		resp := encryptData(b, storage, data, t)

		// get the actual Json key used from teh config for address
		encryptedData := resp.Data["test7-address4"].(string)

		// create an aead keyhandle from the provided json as string
		_, a, err := CreateInsecureHandleAndAead(rawKeyset)
		if err != nil {
			log.Fatal(err)
		}

		// set up some data
		ct, _ := b64.StdEncoding.DecodeString(encryptedData)
		// ct := []byte(encryptedData)
		aad := []byte("test7-address4")

		// decrypt the encrypted data
		pt, err := a.Decrypt(ct, aad)
		if err != nil {
			log.Fatal(err)
		}

		// does the decrypted data match the original data
		if string(pt) != "my address" {
			t.Errorf("expected 'my address' got %s", pt)
		}
	})

	t.Run("test8 encrypt and decrypt deterministic", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		// create a dynamic AEAD key for a field
		// set some data to be encrypted using the keys

		key := "test8-det-town"
		value := "det-my-town"

		data := map[string]interface{}{
			key: value,
		}

		encryptDataDetermisticallyAndCreateKey(b, storage, data, false, t)

		// encrypt the data
		respEncrypt := encryptData(b, storage, data, t)

		// decrypt the data
		respDecrypt := decryptData(b, storage, respEncrypt, t)

		if value != fmt.Sprintf("%s", respDecrypt.Data[key]) {
			t.Error("decrypted data is not the same as original data")
		}

	})

	t.Run("test9 encrypt and decrypt non-deterministic", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		// create a dynamic AEAD key for a field
		// set some data to be encrypted using the keys

		key := "test9-town"
		value := "my town"

		data := map[string]interface{}{
			key: value,
		}

		encryptDataNonDetermisticallyAndCreateKey(b, storage, data, false, t)

		// encrypt the data
		respEncrpt := encryptData(b, storage, data, t)

		// decrypt the data
		respDecrpt := decryptData(b, storage, respEncrpt, t)

		if value != fmt.Sprintf("%s", respDecrpt.Data[key]) {
			t.Error("decrypted data is not the same as original data")
		}

	})

	t.Run("test10 encrypt and decrypt non-deterministic AND deterministic", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		// create a dynamic AEAD key for a field
		// set some data to be encrypted using the keys

		key1 := "test10-myid1"
		value1 := "myid-value"
		key2 := "test10-myid2"
		value2 := "myid-value"

		// configData := map[string]interface{}{
		// 	"KEYTYPE-" + key1: "DAEAD",
		// }

		// saveConfig(b, storage, configData, t)

		deterministicData := map[string]interface{}{
			key1: value1,
		}
		// create the deterministic key for key1
		encryptDataDetermisticallyAndCreateKey(b, storage, deterministicData, false, t)

		nonDeterministicData := map[string]interface{}{
			key2: value2,
		}
		// create the deterministic key for key1
		encryptDataNonDetermisticallyAndCreateKey(b, storage, nonDeterministicData, false, t)

		data := map[string]interface{}{
			key1: value1,
			key2: value2,
		}

		// encrypt the data (key1 = deterministic; key2 = non deterministic)
		respEncrpt := encryptData(b, storage, data, t)

		// decrypt the data
		respDecrpt := decryptData(b, storage, respEncrpt, t)

		if value1 != fmt.Sprintf("%s", respDecrpt.Data[key1]) {
			t.Error("decrypted data is not the same as original data")
		}

		if value2 != fmt.Sprintf("%s", respDecrpt.Data[key2]) {
			t.Error("decrypted data is not the same as original data")
		}
	})

	t.Run("test11 rotate the AEAD keys within a keyset", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		rawKeyset := `{"primaryKeyId":1416257722,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiBa0wZ4ACjtW137qTVSY2ofQBCffdzkzhNkktlMtDFazA==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1416257722,"outputPrefixType":"TINK"}]}`
		primaryKey := "1416257722"
		fieldName := "aeadkeyset1"

		rotateKeySet(fieldName, rawKeyset, b, storage, t, primaryKey)

	})

	t.Run("test12 rotate the DetAEAD keys within a keyset", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)
		rawKeyset := `{"primaryKeyId":42267057,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkDAEgACCd1/yruZMuI49Eig5Glb5koi0DXgx1mXVALYJWNRn5wYuQR46ggNuMhFfhrJCsddVp/Q7Pot2hvHoaQS","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":42267057,"outputPrefixType":"TINK"}]}`
		primaryKey := "42267057"
		fieldName := "daeadkeyset1"

		rotateKeySet(fieldName, rawKeyset, b, storage, t, primaryKey)

	})

	t.Run("test13 encrypt data with a dynamic key then rotate and encrypt new data then decrypt both encrypted data elements", func(t *testing.T) {
		// t.Parallel()
		// b, storage := testBackend(t)
	})

	t.Run("test14 check keyType non deterministic", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)
		fieldName := "test14-nondetfield1"
		fieldValue := "nondetvalue1"

		data := map[string]interface{}{
			fieldName: fieldValue,
		}
		encryptDataNonDetermisticallyAndCreateKey(b, storage, data, false, t)

		// encrypt the data
		encryptData(b, storage, data, t)

		resp := readKeyTypes(b, storage, t)

		compareStrings(resp, fieldName, "NON DETERMINISTIC", t)

	})

	t.Run("test15 check keyType deterministic", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)
		fieldName := "test15-detfield1"
		fieldValue := "detvalue1"

		data := map[string]interface{}{
			fieldName: fieldValue,
		}

		// encrypt the data
		encryptDataDetermisticallyAndCreateKey(b, storage, data, false, t)

		resp := readKeyTypes(b, storage, t)

		compareStrings(resp, fieldName, "DETERMINISTIC", t)

	})

	t.Run("test16 bulk data ", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		// curl -sk --header "X-Vault-Token: "${VAULT_PLUGIN_TOKEN} --request POST ${VAULT_PLUGIN_URL}/v1/aead-secrets/encrypt -H "Content-Type: application/json" -d '{"0":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"},"1":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"},"2":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"}}'

		// cat perftestdata.json
		// {"0":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"},"1":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"},"2":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"}}%
		// {
		// 	"0": {
		// 	  "bulkfield0": "bulkfieldvalue0",
		// 	  "bulkfield1": "bulkfieldvalue1",
		// 	  "bulkfield2": "bulkfieldvalue2"
		// 	},
		// 	"1": {
		// 	  "bulkfield0": "bulkfieldvalue0",
		// 	  "bulkfield1": "bulkfieldvalue1",
		// 	  "bulkfield2": "bulkfieldvalue2"
		// 	},
		// 	"2": {
		// 	  "bulkfield0": "bulkfieldvalue0",
		// 	  "bulkfield1": "bulkfieldvalue1",
		// 	  "bulkfield2": "bulkfieldvalue2"
		// 	}
		//   }

		// vault write aead-secrets/encrypt @perftestdata.json

		rowNum := 2
		fieldNum := 5
		var inputMap = map[string]interface{}{}
		for i := 0; i < rowNum; i++ {
			is := fmt.Sprintf("%v", i)
			innerMap := map[string]interface{}{}
			inputMap[is] = map[string]interface{}{}
			for j := 0; j < fieldNum; j++ {
				js := fmt.Sprintf("%v", j)
				fieldName := "bulkfield" + js
				innerMap[fieldName] = "bulkfieldvalue" + js
			}
			inputMap[is] = innerMap
		}

		// set up the keys and pause
		for i := 0; i < fieldNum; i++ {
			fieldName := "bulkfield" + fmt.Sprintf("%v", i)
			data := map[string]interface{}{
				fieldName: fieldName,
			}
			// encrypt the data
			encryptDataNonDetermisticallyAndCreateKey(b, storage, data, false, t)
			// encryptData(b, storage, data, t)
		}

		resp := encryptData(b, storage, inputMap, t)

		if len(resp.Data) < 1 {
			t.Error("bulk data returned nothing")
		}

		decryptedResp := decryptData(b, storage, resp, t)

		if !reflect.DeepEqual(inputMap, decryptedResp.Data) {
			t.Errorf("\noriginal %v and decrypted %v dont match", inputMap, decryptedResp.Data)
		}

	})

	t.Run("test17 bulk data columns", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		// curl -sk --header "X-Vault-Token: "${VAULT_PLUGIN_TOKEN} --request POST ${VAULT_PLUGIN_URL}/v1/aead-secrets/encrypt -H "Content-Type: application/json" -d '{"0":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"},"1":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"},"2":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"}}'

		// cat perftestdata.json
		// {"0":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"},"1":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"},"2":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"}}%
		// {
		// 	"0": {
		// 	  "bulkfield0": "bulkfieldvalue0",
		// 	  "bulkfield1": "bulkfieldvalue1",
		// 	  "bulkfield2": "bulkfieldvalue2"
		// 	},
		// 	"1": {
		// 	  "bulkfield0": "bulkfieldvalue0",
		// 	  "bulkfield1": "bulkfieldvalue1",
		// 	  "bulkfield2": "bulkfieldvalue2"
		// 	},
		// 	"2": {
		// 	  "bulkfield0": "bulkfieldvalue0",
		// 	  "bulkfield1": "bulkfieldvalue1",
		// 	  "bulkfield2": "bulkfieldvalue2"
		// 	}
		// }

		rowNum := 2
		fieldNum := 5
		var inputMap = map[string]interface{}{}
		for i := 0; i < rowNum; i++ {
			is := fmt.Sprintf("%v", i)
			innerMap := map[string]interface{}{}
			inputMap[is] = map[string]interface{}{}
			for j := 0; j < fieldNum; j++ {
				js := fmt.Sprintf("%v", j)
				fieldName := "bulkfield" + js
				innerMap[fieldName] = "bulkfieldvalue" + is + "-" + js
			}
			inputMap[is] = innerMap
		}

		// set up the keys and pause
		for i := 0; i < fieldNum; i++ {
			fieldName := "bulkfield" + fmt.Sprintf("%v", i)
			data := map[string]interface{}{
				fieldName: fieldName,
			}
			// encrypt the data
			encryptDataNonDetermisticallyAndCreateKey(b, storage, data, false, t)
			// encryptData(b, storage, data, t)
		}

		resp := encryptDataCol(b, storage, inputMap, t)

		if len(resp.Data) < 1 {
			t.Error("bulk data returned nothing")
		}

		decryptedResp := decryptDataCol(b, storage, resp, t)

		if !reflect.DeepEqual(inputMap, decryptedResp.Data) {
			t.Errorf("\noriginal %v and decrypted %v dont match", inputMap, decryptedResp.Data)
		}

	})

	t.Run("test18 bulk data columns but no keys preset", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		// curl -sk --header "X-Vault-Token: "${VAULT_PLUGIN_TOKEN} --request POST ${VAULT_PLUGIN_URL}/v1/aead-secrets/encrypt -H "Content-Type: application/json" -d '{"0":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"},"1":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"},"2":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"}}'

		// cat perftestdata.json
		// {"0":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"},"1":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"},"2":{"bulkfield0":"bulkfieldvalue0","bulkfield1":"bulkfieldvalue1","bulkfield2":"bulkfieldvalue2"}}%
		// {
		// 	"0": {
		// 	  "bulkfield0": "bulkfieldvalue0",
		// 	  "bulkfield1": "bulkfieldvalue1",
		// 	  "bulkfield2": "bulkfieldvalue2"
		// 	},
		// 	"1": {
		// 	  "bulkfield0": "bulkfieldvalue0",
		// 	  "bulkfield1": "bulkfieldvalue1",
		// 	  "bulkfield2": "bulkfieldvalue2"
		// 	},
		// 	"2": {
		// 	  "bulkfield0": "bulkfieldvalue0",
		// 	  "bulkfield1": "bulkfieldvalue1",
		// 	  "bulkfield2": "bulkfieldvalue2"
		// 	}
		//   }

		// vault write aead-secrets/encrypt @perftestdata.json

		rowNum := 2
		fieldNum := 5
		var inputMap = map[string]interface{}{}
		for i := 0; i < rowNum; i++ {
			is := fmt.Sprintf("%v", i)
			innerMap := map[string]interface{}{}
			inputMap[is] = map[string]interface{}{}
			for j := 0; j < fieldNum; j++ {
				js := fmt.Sprintf("%v", j)
				fieldName := "newbulkfield" + js
				innerMap[fieldName] = "bulkfieldvalue" + is + "-" + js
			}
			inputMap[is] = innerMap
		}

		resp := encryptDataCol(b, storage, inputMap, t)

		if len(resp.Data) < 1 {
			t.Error("bulk data returned nothing")
		}

		decryptedResp := decryptDataCol(b, storage, resp, t)

		if !reflect.DeepEqual(inputMap, decryptedResp.Data) {
			t.Errorf("\noriginal %v and decrypted %v dont match", inputMap, decryptedResp.Data)
		}

	})

	// t.Run("test-bqsync fake test to debug bqsync ", func(t *testing.T) {
	// un comment this if you need to debug bqsync
	// 	// t.Parallel()
	// 	b, storage := testBackend(t)

	// 	data := make(map[string]interface{})

	// 	_, err := b.HandleRequest(context.Background(), &logical.Request{
	// 		Storage:   storage,
	// 		Operation: logical.UpdateOperation,
	// 		Path:      "bqsync",
	// 		Data:      data,
	// 	})
	// 	if err != nil {
	// 		t.Fatal("bqsync", err)
	// 	}
	// })

	t.Run("test19 test config and bq override-no-override ", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		aeadRequest := make(map[string]interface{})

		// set up some config
		aeadRequest["test19-aead"] = "junktext"

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "createAEADkey",
			Data:      aeadRequest,
		})
		if err != nil {
			t.Fatal("create AEAD key", err)
		}

		daeadRequest := make(map[string]interface{})

		// set up some config
		daeadRequest["test19-daead"] = "junktext"

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "createDAEADkey",
			Data:      daeadRequest,
		})
		if err != nil {
			t.Fatal("create DAEAD key", err)
		}

		configRequest := map[string]interface{}{
			"test19-config": "someconfig",
		}

		saveConfig(b, storage, configRequest, false, t)

		resp := readConfig(b, storage, t)

		if resp == nil {
			t.Fatal("read back storage", err)
		}

		baselineAeadValue, ok := resp.Data["test19-aead"]
		if !ok {
			t.Fatal("read back baselineAeadValue", err)
		}
		baselineDaeadValue, ok := resp.Data["test19-daead"]
		if !ok {
			t.Fatal("read back baselineDaeadValue", err)
		}
		baselineConfigValue, ok := resp.Data["test19-config"]
		if !ok {
			t.Fatal("read back baselineConfigValue", err)
		}

		// try to make new data - should not override
		encryptDataNonDetermisticallyAndCreateKey(b, storage, aeadRequest, false, t)
		encryptDataDetermisticallyAndCreateKey(b, storage, daeadRequest, false, t)
		configRequest2 := map[string]interface{}{
			"test19-config": "someconfig2",
		}

		saveConfig(b, storage, configRequest2, false, t)

		resp = readConfig(b, storage, t)

		if resp == nil {
			t.Fatal("read back storage", err)
		}

		newAeadValue, ok := resp.Data["test19-aead"]
		if !ok {
			t.Fatal("read back baselineAeadValue", err)
		}
		newDaeadValue, ok := resp.Data["test19-daead"]
		if !ok {
			t.Fatal("read back baselineDaeadValue", err)
		}
		newConfigValue, ok := resp.Data["test19-config"]
		if !ok {
			t.Fatal("read back baselineConfigValue", err)
		}

		if fmt.Sprintf("%s", baselineAeadValue) != fmt.Sprintf("%s", newAeadValue) ||
			fmt.Sprintf("%s", baselineDaeadValue) != fmt.Sprintf("%s", newDaeadValue) ||
			fmt.Sprintf("%s", baselineConfigValue) != fmt.Sprintf("%s", newConfigValue) {
			t.Fatal("read back config values and they are different", err)
		}

		// try to make new data - should not override
		encryptDataNonDetermisticallyAndCreateKey(b, storage, aeadRequest, true, t)
		encryptDataDetermisticallyAndCreateKey(b, storage, daeadRequest, true, t)
		configRequest3 := map[string]interface{}{
			"test19-config": "someconfig3",
		}
		saveConfig(b, storage, configRequest3, true, t)

		resp = readConfig(b, storage, t)

		if resp == nil {
			t.Fatal("read back storage", err)
		}

		newAeadValue, ok = resp.Data["test19-aead"]
		if !ok {
			t.Fatal("read back baselineAeadValue", err)
		}
		newDaeadValue, ok = resp.Data["test19-daead"]
		if !ok {
			t.Fatal("read back baselineDaeadValue", err)
		}
		newConfigValue, ok = resp.Data["test19-config"]
		if !ok {
			t.Fatal("read back baselineConfigValue", err)
		}

		if fmt.Sprintf("%s", baselineAeadValue) == fmt.Sprintf("%s", newAeadValue) ||
			fmt.Sprintf("%s", baselineDaeadValue) == fmt.Sprintf("%s", newDaeadValue) ||
			fmt.Sprintf("%s", baselineConfigValue) == fmt.Sprintf("%s", newConfigValue) {
			t.Fatal("read back config values and they are NOT different", err)
		}

		// t.Run("test20 test config delete", func(t *testing.T) {
		// // this is commented out as delete does not work
		// 	// t.Parallel()
		// 	b, storage := testBackend(t)

		// 	configRequest := map[string]interface{}{
		// 		"test20-config": "someconfig",
		// 	}

		// 	saveConfig(b, storage, configRequest, false, t)

		// 	resp := readConfig(b, storage, t)

		// 	if resp == nil {
		// 		t.Fatal("read back storage", err)
		// 	}

		// 	_, ok := resp.Data["test20-config"]
		// 	if !ok {
		// 		t.Fatal("read back baselineConfigValue", err)
		// 	}

		// 	deleteConfig(b, storage, configRequest, t)

		// 	resp = readConfig(b, storage, t)

		// 	if resp == nil {
		// 		t.Fatal("read back storage", err)
		// 	}

		// 	_, ok = resp.Data["test20-config"]
		// 	if ok {
		// 		t.Fatal("failed to delete config", err)
		// 	}
		// })

	})

}

func rotateKeySet(fieldName string, rawKeyset string, b *backend, storage logical.Storage, t *testing.T, primaryKey string) {
	configData := map[string]interface{}{
		fieldName: rawKeyset,
	}

	saveConfig(b, storage, configData, false, t)

	rotateConfigKeys(b, storage, configData, t)

	resp := readConfig(b, storage, t)

	keySet := resp.Data[fieldName]
	keySetStr := fmt.Sprintf("%s", keySet)

	// the primary Key should have changed
	if strings.Contains(keySetStr, "\"primaryKeyId\":"+primaryKey) {
		t.Errorf("written keyset %s still contains primaryKeyId :%s", keySetStr, primaryKey)
	}
}

func readInfo(b *backend, storage logical.Storage, t *testing.T) *logical.Response {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "info",
	})
	if err != nil {
		t.Fatal("readInfo", err)
	}
	return resp
}

func compareStrings(resp *logical.Response, responseField string, exp string, t *testing.T) {
	if v, exp := resp.Data[responseField].(string), exp; v != exp {

		t.Errorf("expected %q to be %q", v, exp)
	}
}

func decryptData(b *backend, storage logical.Storage, respEncrypt *logical.Response, t *testing.T) *logical.Response {
	respDecrypt, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "decrypt",
		Data:      respEncrypt.Data,
	})

	if err != nil {
		t.Fatal("decryptData", err)
	}
	return respDecrypt
}

func encryptData(b *backend, storage logical.Storage, data map[string]interface{}, t *testing.T) *logical.Response {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "encrypt",
		Data:      data,
	})

	if err != nil {
		t.Fatal("encryptData", err)
	}
	return resp
}

func decryptDataCol(b *backend, storage logical.Storage, respEncrypt *logical.Response, t *testing.T) *logical.Response {
	respDecrypt, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "decryptcol",
		Data:      respEncrypt.Data,
	})

	if err != nil {
		t.Fatal("decryptDataCol", err)
	}
	return respDecrypt
}

func encryptDataCol(b *backend, storage logical.Storage, data map[string]interface{}, t *testing.T) *logical.Response {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "encryptcol",
		Data:      data,
	})

	if err != nil {
		t.Fatal("encryptDataCol", err)
	}
	return resp
}

func encryptDataDetermisticallyAndCreateKey(b *backend, storage logical.Storage, data map[string]interface{}, overwrite bool, t *testing.T) *logical.Response {

	pathEndpoint := "createDAEADkey"
	if overwrite {
		pathEndpoint = "createDAEADkeyOverwrite"
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      pathEndpoint,
		Data:      data,
	})

	if err != nil {
		t.Fatal("encryptDataDetermistically", err)
	}
	return resp
}

func encryptDataNonDetermisticallyAndCreateKey(b *backend, storage logical.Storage, data map[string]interface{}, overwrite bool, t *testing.T) *logical.Response {

	pathEndpoint := "createAEADkey"
	if overwrite {
		pathEndpoint = "createAEADkeyOverwrite"
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      pathEndpoint,
		Data:      data,
	})

	if err != nil {
		t.Fatal("encryptDataNonDetermistically", err)
	}
	return resp
}

func readConfig(b *backend, storage logical.Storage, t *testing.T) *logical.Response {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "config",
	})
	if err != nil {
		t.Fatal("readConfig", err)
	}
	return resp
}

func readKeyTypes(b *backend, storage logical.Storage, t *testing.T) *logical.Response {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "keytypes",
	})
	if err != nil {
		t.Fatal("readKeyTypes", err)
	}
	return resp
}

func saveConfig(b *backend, storage logical.Storage, data map[string]interface{}, overwrite bool, t *testing.T) {

	pathEndpoint := "config"
	if overwrite {
		pathEndpoint = "configOverwrite"
	}
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      pathEndpoint,
		Data:      data,
	})
	if err != nil {
		t.Fatal("saveConfig", err)
	}
}

func deleteConfig(b *backend, storage logical.Storage, data map[string]interface{}, t *testing.T) {

	pathEndpoint := "configDelete"

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      pathEndpoint,
		Data:      data,
	})
	if err != nil {
		t.Fatal("deleteConfig", err)
	}
}

func storeKeyValue(secretKey string, secretValue string, t *testing.T) {
	data := map[string]interface{}{
		secretKey: secretValue,
	}

	b, storage := testBackend(t)

	saveConfig(b, storage, data, true, t)

	resp := readConfig(b, storage, t)

	if v, secretValue := resp.Data[secretKey].(string), secretValue; v != secretValue {

		t.Errorf("expected %q to be %q", v, secretValue)
	}

}

func rotateConfigKeys(b *backend, storage logical.Storage, data map[string]interface{}, t *testing.T) {
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "rotate",
		Data:      data,
	})
	if err != nil {
		t.Fatal("rotateConfigKeys", err)
	}
}
