package aeadplugin

import (
	"bytes"
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/bigquery"
	"github.com/Vodafone/vault-plugin-aead/aeadutils"
	"github.com/Vodafone/vault-plugin-aead/kvutils"
	version "github.com/Vodafone/vault-plugin-aead/version"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/logical"
)

/*
how to set up a local vault for testing
run the make file - this starts a local vault
then in another shell
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root
vault login

create the policy file for the approle and secret:
cat policy.json
path "secret/*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list"]
}
path "transit/*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list"]
}

cat secretgenpolicy.json
path "auth/approle/role/my-approle/secret-id" {
  capabilities = ["create", "update"]
}


vault secrets enable -path=aead-secrets vault-plugin-aead
vault secrets enable transit
vault write -f transit/keys/my-key
vault auth enable approle
vault policy write my-policy ./policy.json
vault write auth/approle/role/my-approle token_policies="my-policy"
vault read -field=role_id auth/approle/role/my-approle/role-id
vault write -f -field=secret_id auth/approle/role/my-approle/secret-id
vault kv put -mount=secret transit-token key=root

vault auth enable gcp
vault policy write secretgen-policy ./policy-secretgen.json
vault write auth/gcp/role/vault-gce-auth-role type="gce" policies="secretgen-policy" bound_service_accounts="restricted-zone-restricted@vf-grp-neuronenabler-nonlive.iam.gserviceaccount.com"
*/

// NOTE THE BELOW VALUES ARE FOR A LOCAL VAULT, INSTRUCTIONS ABOVE
// YOU WILL NEED TO ADJUST YOUR VALUES ACCORDINGLY
// YOU WILL HAVE DIFFERENT approle AND secret id

const vault_kv_url string = "https://zzz.vodafone.com"
const vault_kv_active string = "false"
const vault_kv_approle_id string = "xxxxxx"
const vault_kv_secret_id string = "yyyyyy"
const vault_kv_engine string = "secret"
const vault_kv_version string = "v2"
const vault_kv_writer_role = "kv-writer-role"
const vault_secretgenerator_iam_role = "secretgenerator-iam-role"

const vault_transit_active string = "false"
const vault_transit_url string = "http://localhost:8200"
const vault_transit_kv_approle_id string = "xxxxxx"
const vault_transit_kv_secret_id string = "yyyyyy"
const vault_transit_kv_engine string = "secret"
const vault_transit_kv_version string = "v2"
const vault_transit_namespace string = ""
const vault_transit_engine string = "transit"
const vault_transit_kek string = "my-key"

const bq_active string = "false"

const DeterministicKeyset = `{"primaryKeyId":97978150,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkALk9CVIh1NDBjiE+gBvL/+aJuCdFRZQBzQSp5DcVy/4DkhrGF7BKdt0xLxjyX4jIKN2Vki1rSza+ETgGPV4zLD","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1481824018,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkCXhcXHvfUMj8DWgWjfnxyWFz3GcOw8G1xB2PTcfPdbl93idxHTcmANzYLYW3KmsU0putTRfi3vxySALhSHaHl0","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3647454112,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkDeUHhnPioOIETPIbKfEcifAjnhxaeUJbRwT/TB6AurJG/qmhsbpGaHKFdhDHn6VtJ7I/tMWX7gFZTr1Db9f/3v","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":4039363563,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkAqIqBlB7q0W/bhp9RtivX770+nAYkEWxBkYjfPzbWiBWJZbM7YypfHbkOyyWPtkBc0yVK0YTUmqbWD0JpEJ63u","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3167099089,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkDfF2JLaeZPvRwMncPw8ZKhsoGDMvFDriu7RtdF1pgHvRefGKbAa56pU7IFQCzA+UWy+dBNtsLW2H5rbHsxM2FC","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":2568362933,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkC9CVw73BjO+OSjo3SFvUV7SUszpJnuKGnLWMbmD7cO3WFCIy2unxoyNPCHFDlzle1zU35vTZtoecnlsWScQUVl","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":97978150,"outputPrefixType":"TINK"}]}`
const NonDeterministicKeyset = `{"primaryKeyId":3192631270,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiBf14hIKBzJYUGjc4LXzaG3dT3aVsvv0vpyZJVZNh02MQ==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":2832419897,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiCW0m5ElDr8RznAl4ef3bXqgHgu9PL/js7K6NAZIjkDJw==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":2233686170,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiChGSKGi7odjL3mdwhQ03X5SGiVXTarRSKPZUn+xCUYyQ==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1532149397,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiApAwR1VAPVxpIrRiBGw2RziWx04nzHVDYu1ocipSDCvQ==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3192631270,"outputPrefixType":"TINK"}]}`
const DeterministicSingleKey = `{"primaryKeyId":1481824018,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkALk9CVIh1NDBjiE+gBvL/+aJuCdFRZQBzQSp5DcVy/4DkhrGF7BKdt0xLxjyX4jIKN2Vki1rSza+ETgGPV4zLD","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1481824018,"outputPrefixType":"TINK"}]}`

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

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

		encryptionJsonKey := `{"primaryKeyId":42267057,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkDAEgACCd1/yruZMuI49Eig5Glb5koi0DXgx1mXVALYJWNRn5wYuQR46ggNuMhFfhrJCsddVp/Q7Pot2hvHoaQS","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":42267057,"outputPrefixType":"TINK"}]}`
		// set up some encryption keys to be used
		encryptionMap := map[string]interface{}{
			"test4-address":     "siv/test4-address",
			"siv/test4-address": encryptionJsonKey,
			"test4-phone":       "siv/test4-phone",
			"siv/test4-phone":   encryptionJsonKey,
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
		h, d, err := aeadutils.CreateInsecureHandleAndDeterministicAead(encryptionJsonKey)
		if err != nil {
			log.Fatal(err)
		}

		ki := h.KeysetInfo().KeyInfo
		for k, v := range ki {
			fmt.Printf("k=%v; v=%v", k, v.GetTypeUrl())
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

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

		// Since we now mask material from the response, we will use existing key to make sure string is encrypted correctly
		encryptionJsonKey := `{"primaryKeyId":42267057,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkDAEgACCd1/yruZMuI49Eig5Glb5koi0DXgx1mXVALYJWNRn5wYuQR46ggNuMhFfhrJCsddVp/Q7Pot2hvHoaQS","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":42267057,"outputPrefixType":"TINK"}]}`
		// set up some encryption keys to be used
		encryptionMap := map[string]interface{}{
			"test5-address2":     "siv/test5-address2",
			"siv/test5-address2": encryptionJsonKey,
		}
		// store the config
		saveConfig(b, storage, encryptionMap, false, t)

		// set some data to be encrypted using the keys
		data := map[string]interface{}{
			"test5-address2": "my address",
			"test5-phone2":   "my phone",
		}

		resp := encryptDataDetermisticallyAndCreateKey(b, storage, data, false, t)

		// retreive the encrypted data for field address
		actualEncryptedValue := fmt.Sprintf("%v", resp.Data["test5-address2"]) // convert the cyphertext (=interface{}) received to a string
		keyAlreadyExistsMsg := "test5-address2 key exists"
		if keyAlreadyExistsMsg != actualEncryptedValue {
			t.Errorf("expected %q to be %q", actualEncryptedValue, keyAlreadyExistsMsg)
		}
		resp = encryptData(b, storage, data, t)
		actualEncryptedValue = fmt.Sprintf("%v", resp.Data["test5-address2"])

		// now read the config
		configResp := readConfig(b, storage, t)

		// get the actual Json key used from teh config for address
		actualJSonKey := configResp.Data["siv/test5-address2"].(string)
		type jsonKey struct {
			Key []struct {
				KeyData struct {
					Value string `json:"value"`
				} `json:"keyData"`
			} `json:"key"`
		}
		var result jsonKey
		err := json.Unmarshal([]byte(actualJSonKey), &result)
		if err != nil {
			panic(err)
		}
		// make sure the material response is masked
		maskString := "***"
		if result.Key[0].KeyData.Value != maskString {
			t.Errorf("expected %q to be %q", result.Key[0].KeyData.Value, maskString)
		}

		// re-encrypt the data using our known key
		_, d, err := aeadutils.CreateInsecureHandleAndDeterministicAead(encryptionJsonKey)
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

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

		// create a dynamic AEAD key for a field
		// set some data to be encrypted using the keys
		data := map[string]interface{}{
			"test6-address3": "my address",
		}

		encryptDataNonDetermisticallyAndCreateKey(b, storage, data, false, t)

		keyMap := map[string]interface{}{
			"test6-address3": "gcm/test6-address3",
		}
		// store the config
		saveConfig(b, storage, keyMap, false, t)

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
		actualJSonKey := configResp.Data["gcm/test6-address3"].(string)

		if !strings.Contains(actualJSonKey, "AesGcmKey") {
			t.Error("key is not a AesGcmKey")
		}

	})

	t.Run("test7 non-deterministic encryption with supplied AEAD key", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

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

		keyMap := map[string]interface{}{
			"test7-address4": "gcm/test7-address4",
		}
		// store the config
		saveConfig(b, storage, keyMap, false, t)

		data := map[string]interface{}{
			"test7-address4": "my address",
		}

		// encrypt the data
		resp := encryptData(b, storage, data, t)

		// get the actual Json key used from teh config for address
		encryptedData := resp.Data["test7-address4"].(string)

		// create an aead keyhandle from the provided json as string
		_, a, err := aeadutils.CreateInsecureHandleAndAead(rawKeyset)
		if err != nil {
			t.Errorf("Failed to create aead from %s", rawKeyset)
		}

		// set up some data
		ct, _ := b64.StdEncoding.DecodeString(encryptedData)
		// ct := []byte(encryptedData)
		aad := []byte("test7-address4")

		// decrypt the encrypted data
		pt, err := a.Decrypt(ct, aad)
		if err != nil {
			t.Errorf("Failed to decrypt %s", encryptedData)
		}

		// does the decrypted data match the original data
		if string(pt) != "my address" {
			t.Errorf("expected 'my address' got %s", pt)
		}
	})

	t.Run("test8 encrypt and decrypt deterministic", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

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

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

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

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

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

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

		rawKeyset := `{"primaryKeyId":1416257722,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiBa0wZ4ACjtW137qTVSY2ofQBCffdzkzhNkktlMtDFazA==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1416257722,"outputPrefixType":"TINK"}]}`
		primaryKey := "1416257722"
		fieldName := "aeadkeyset1"

		rotateKeySet(fieldName, rawKeyset, b, storage, t, primaryKey)

	})

	t.Run("test12 rotate the DetAEAD keys within a keyset", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

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

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

		fieldName := "test14-nondetfield1"
		fieldValue := "nondetvalue1"

		data := map[string]interface{}{
			fieldName: fieldValue,
		}
		encryptDataNonDetermisticallyAndCreateKey(b, storage, data, false, t)

		// encrypt the data
		encryptData(b, storage, data, t)

		resp := readKeyTypes(b, storage, t)

		compareStrings(resp, "gcm/"+fieldName, "NON DETERMINISTIC", t)

	})

	t.Run("test15 check keyType deterministic", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

		fieldName := "test15-detfield1"
		fieldValue := "detvalue1"

		data := map[string]interface{}{
			fieldName: fieldValue,
		}

		// encrypt the data
		encryptDataDetermisticallyAndCreateKey(b, storage, data, false, t)

		resp := readKeyTypes(b, storage, t)

		compareStrings(resp, "siv/"+fieldName, "DETERMINISTIC", t)

	})

	t.Run("test16 bulk data ", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

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

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

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

	t.Run("test19 test config and bq override-no-override ", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

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

		keyMap := map[string]interface{}{
			"test19-aead": "gcm/test19-aead",
		}
		// store the config
		saveConfig(b, storage, keyMap, false, t)

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
			"test19-daead":  "siv/test19-daead",
			"test19-config": "someconfig",
		}

		saveConfig(b, storage, configRequest, false, t)

		resp := readConfig(b, storage, t)

		if resp == nil {
			t.Fatal("read back storage", err)
		}

		baselineAeadValue, ok := resp.Data["gcm/test19-aead"]
		if !ok {
			t.Fatal("read back baselineAeadValue", err)
		}
		baselineDaeadValue, ok := resp.Data["siv/test19-daead"]
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

		newAeadValue, ok := resp.Data["gcm/test19-aead"]
		if !ok {
			t.Fatal("read back baselineAeadValue", err)
		}
		newDaeadValue, ok := resp.Data["siv/test19-daead"]
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

		newAeadValue, ok = resp.Data["gcm/test19-aead"]
		if !ok {
			t.Fatal("read back baselineAeadValue", err)
		}
		newDaeadValue, ok = resp.Data["siv/test19-daead"]
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
	})
	t.Run("test20 test config delete", func(t *testing.T) {
		// this is commented out as delete does not work
		// t.Parallel()
		b, storage := testBackend(t)

		configRequest := map[string]interface{}{
			"test20-config": "someconfig",
		}

		saveConfig(b, storage, configRequest, false, t)

		resp := readConfig(b, storage, t)

		if resp == nil {
			t.Fatal("read back storage")
		}

		_, ok := resp.Data["test20-config"]
		if !ok {
			t.Fatal("read back baselineConfigValue")
		}

		deleteConfig(b, storage, configRequest, t)

		resp2 := readConfig(b, storage, t)

		if resp2 == nil {
			t.Fatal("read back storage")
		}

		_, ok = resp2.Data["test20-config"]
		if ok {
			t.Fatal("failed to delete config")
		}
	})
	// for the key ops below we will use
	// NON-DETERMINISTIC:
	// {"primaryKeyId":3192631270,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiBf14hIKBzJYUGjc4LXzaG3dT3aVsvv0vpyZJVZNh02MQ==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":2832419897,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiCW0m5ElDr8RznAl4ef3bXqgHgu9PL/js7K6NAZIjkDJw==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":2233686170,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiChGSKGi7odjL3mdwhQ03X5SGiVXTarRSKPZUn+xCUYyQ==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1532149397,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiApAwR1VAPVxpIrRiBGw2RziWx04nzHVDYu1ocipSDCvQ==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3192631270,"outputPrefixType":"TINK"}]}
	// {
	// 	"primaryKeyId": 3192631270,
	// 	"key": [
	// 	  {
	// 		"keyData": {
	// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
	// 		  "value": "GiBf14hIKBzJYUGjc4LXzaG3dT3aVsvv0vpyZJVZNh02MQ==",
	// 		  "keyMaterialType": "SYMMETRIC"
	// 		},
	// 		"status": "ENABLED",
	// 		"keyId": 2832419897,
	// 		"outputPrefixType": "TINK"
	// 	  },
	// 	  {
	// 		"keyData": {
	// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
	// 		  "value": "GiCW0m5ElDr8RznAl4ef3bXqgHgu9PL/js7K6NAZIjkDJw==",
	// 		  "keyMaterialType": "SYMMETRIC"
	// 		},
	// 		"status": "ENABLED",
	// 		"keyId": 2233686170,
	// 		"outputPrefixType": "TINK"
	// 	  },
	// 	  {
	// 		"keyData": {
	// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
	// 		  "value": "GiChGSKGi7odjL3mdwhQ03X5SGiVXTarRSKPZUn+xCUYyQ==",
	// 		  "keyMaterialType": "SYMMETRIC"
	// 		},
	// 		"status": "ENABLED",
	// 		"keyId": 1532149397,
	// 		"outputPrefixType": "TINK"
	// 	  },
	// 	  {
	// 		"keyData": {
	// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
	// 		  "value": "GiApAwR1VAPVxpIrRiBGw2RziWx04nzHVDYu1ocipSDCvQ==",
	// 		  "keyMaterialType": "SYMMETRIC"
	// 		},
	// 		"status": "ENABLED",
	// 		"keyId": 3192631270,
	// 		"outputPrefixType": "TINK"
	// 	  }
	// 	]
	//   }
	// or
	// DETERMINISTIC
	// {"primaryKeyId":97978150,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkALk9CVIh1NDBjiE+gBvL/+aJuCdFRZQBzQSp5DcVy/4DkhrGF7BKdt0xLxjyX4jIKN2Vki1rSza+ETgGPV4zLD","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1481824018,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkCXhcXHvfUMj8DWgWjfnxyWFz3GcOw8G1xB2PTcfPdbl93idxHTcmANzYLYW3KmsU0putTRfi3vxySALhSHaHl0","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3647454112,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkDeUHhnPioOIETPIbKfEcifAjnhxaeUJbRwT/TB6AurJG/qmhsbpGaHKFdhDHn6VtJ7I/tMWX7gFZTr1Db9f/3v","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":4039363563,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkAqIqBlB7q0W/bhp9RtivX770+nAYkEWxBkYjfPzbWiBWJZbM7YypfHbkOyyWPtkBc0yVK0YTUmqbWD0JpEJ63u","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3167099089,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkDfF2JLaeZPvRwMncPw8ZKhsoGDMvFDriu7RtdF1pgHvRefGKbAa56pU7IFQCzA+UWy+dBNtsLW2H5rbHsxM2FC","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":2568362933,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkC9CVw73BjO+OSjo3SFvUV7SUszpJnuKGnLWMbmD7cO3WFCIy2unxoyNPCHFDlzle1zU35vTZtoecnlsWScQUVl","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":97978150,"outputPrefixType":"TINK"}]}
	// {
	// 	"primaryKeyId": 97978150,
	// 	"key": [
	// 	  {
	// 		"keyData": {
	// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesSivKey",
	// 		  "value": "EkALk9CVIh1NDBjiE+gBvL/+aJuCdFRZQBzQSp5DcVy/4DkhrGF7BKdt0xLxjyX4jIKN2Vki1rSza+ETgGPV4zLD",
	// 		  "keyMaterialType": "SYMMETRIC"
	// 		},
	// 		"status": "ENABLED",
	// 		"keyId": 1481824018,
	// 		"outputPrefixType": "TINK"
	// 	  },
	// 	  {
	// 		"keyData": {
	// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesSivKey",
	// 		  "value": "EkCXhcXHvfUMj8DWgWjfnxyWFz3GcOw8G1xB2PTcfPdbl93idxHTcmANzYLYW3KmsU0putTRfi3vxySALhSHaHl0",
	// 		  "keyMaterialType": "SYMMETRIC"
	// 		},
	// 		"status": "ENABLED",
	// 		"keyId": 3647454112,
	// 		"outputPrefixType": "TINK"
	// 	  },
	// 	  {
	// 		"keyData": {
	// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesSivKey",
	// 		  "value": "EkDeUHhnPioOIETPIbKfEcifAjnhxaeUJbRwT/TB6AurJG/qmhsbpGaHKFdhDHn6VtJ7I/tMWX7gFZTr1Db9f/3v",
	// 		  "keyMaterialType": "SYMMETRIC"
	// 		},
	// 		"status": "ENABLED",
	// 		"keyId": 4039363563,
	// 		"outputPrefixType": "TINK"
	// 	  },
	// 	  {
	// 		"keyData": {
	// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesSivKey",
	// 		  "value": "EkAqIqBlB7q0W/bhp9RtivX770+nAYkEWxBkYjfPzbWiBWJZbM7YypfHbkOyyWPtkBc0yVK0YTUmqbWD0JpEJ63u",
	// 		  "keyMaterialType": "SYMMETRIC"
	// 		},
	// 		"status": "ENABLED",
	// 		"keyId": 3167099089,
	// 		"outputPrefixType": "TINK"
	// 	  },
	// 	  {
	// 		"keyData": {
	// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesSivKey",
	// 		  "value": "EkDfF2JLaeZPvRwMncPw8ZKhsoGDMvFDriu7RtdF1pgHvRefGKbAa56pU7IFQCzA+UWy+dBNtsLW2H5rbHsxM2FC",
	// 		  "keyMaterialType": "SYMMETRIC"
	// 		},
	// 		"status": "ENABLED",
	// 		"keyId": 2568362933,
	// 		"outputPrefixType": "TINK"
	// 	  },
	// 	  {
	// 		"keyData": {
	// 		  "typeUrl": "type.googleapis.com/google.crypto.tink.AesSivKey",
	// 		  "value": "EkC9CVw73BjO+OSjo3SFvUV7SUszpJnuKGnLWMbmD7cO3WFCIy2unxoyNPCHFDlzle1zU35vTZtoecnlsWScQUVl",
	// 		  "keyMaterialType": "SYMMETRIC"
	// 		},
	// 		"status": "ENABLED",
	// 		"keyId": 97978150,
	// 		"outputPrefixType": "TINK"
	// 	  }
	// 	]
	//   }

	// const DeterministicKeyset = `{"primaryKeyId":97978150,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkALk9CVIh1NDBjiE+gBvL/+aJuCdFRZQBzQSp5DcVy/4DkhrGF7BKdt0xLxjyX4jIKN2Vki1rSza+ETgGPV4zLD","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1481824018,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkCXhcXHvfUMj8DWgWjfnxyWFz3GcOw8G1xB2PTcfPdbl93idxHTcmANzYLYW3KmsU0putTRfi3vxySALhSHaHl0","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3647454112,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkDeUHhnPioOIETPIbKfEcifAjnhxaeUJbRwT/TB6AurJG/qmhsbpGaHKFdhDHn6VtJ7I/tMWX7gFZTr1Db9f/3v","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":4039363563,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkAqIqBlB7q0W/bhp9RtivX770+nAYkEWxBkYjfPzbWiBWJZbM7YypfHbkOyyWPtkBc0yVK0YTUmqbWD0JpEJ63u","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3167099089,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkDfF2JLaeZPvRwMncPw8ZKhsoGDMvFDriu7RtdF1pgHvRefGKbAa56pU7IFQCzA+UWy+dBNtsLW2H5rbHsxM2FC","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":2568362933,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkC9CVw73BjO+OSjo3SFvUV7SUszpJnuKGnLWMbmD7cO3WFCIy2unxoyNPCHFDlzle1zU35vTZtoecnlsWScQUVl","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":97978150,"outputPrefixType":"TINK"}]}`
	// const NonDeterministicKeyset = `{"primaryKeyId":3192631270,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiBf14hIKBzJYUGjc4LXzaG3dT3aVsvv0vpyZJVZNh02MQ==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":2832419897,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiCW0m5ElDr8RznAl4ef3bXqgHgu9PL/js7K6NAZIjkDJw==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":2233686170,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiChGSKGi7odjL3mdwhQ03X5SGiVXTarRSKPZUn+xCUYyQ==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1532149397,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiApAwR1VAPVxpIrRiBGw2RziWx04nzHVDYu1ocipSDCvQ==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3192631270,"outputPrefixType":"TINK"}]}`
	// const DeterministicSingleKey = `{"primaryKeyId":1481824018,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkALk9CVIh1NDBjiE+gBvL/+aJuCdFRZQBzQSp5DcVy/4DkhrGF7BKdt0xLxjyX4jIKN2Vki1rSza+ETgGPV4zLD","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1481824018,"outputPrefixType":"TINK"}]}`

	t.Run("test21 pathUpdateKeyStatus deterministic", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

		keyData := make(map[string]interface{})
		keyData["test21-key"] = DeterministicSingleKey

		keyResp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "importKey",
			Data:      keyData,
		})

		if err != nil {
			t.Fatal("importKey", err)
		}

		if len(keyResp.Data) == 0 {
			t.Fatal("importKey - no data returned")

		}

		keyMap := map[string]interface{}{
			"test21-key": "siv/test21-key",
		}
		// store the config
		saveConfig(b, storage, keyMap, false, t)

		updData := make(map[string]interface{})
		upDataInner := make(map[string]interface{})
		upDataInner["1481824018"] = "DISABLED"
		updData["test21-key"] = upDataInner

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "updateKeyStatus",
			Data:      updData,
		})

		if err != nil {
			t.Fatal("updateKeyStatus", err)
		}

		resp := readConfig(b, storage, t)

		if len(resp.Data) == 0 {
			t.Fatal("updateKeyStatus - no data returned")
		}

		str := fmt.Sprintf("%s", resp.Data)
		if !strings.Contains(str, "\"status\":\"DISABLED\"") {
			t.Errorf("statuswas not changed %s", str)
		}

	})

	t.Run("test22 pathUpdateKeyMaterial non-deterministic", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

		keyData := make(map[string]interface{})
		keyData["test22-key"] = DeterministicKeyset

		// create deterministic key
		keyResp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "importKey",
			Data:      keyData,
		})

		if err != nil {
			t.Fatal("importKey", err)
		}

		if len(keyResp.Data) == 0 {
			t.Fatal("importKey - no data returned")

		}

		keyMap := map[string]interface{}{
			"test22-key": "siv/test22-key",
		}
		// store the config
		saveConfig(b, storage, keyMap, false, t)

		// encrypt data with deterministic key
		data := map[string]interface{}{
			"test22-key": "the data that will test the changed key",
		}
		respValueOrig := encryptData(b, storage, data, t)
		valueEncryptedWithOriginalKey := fmt.Sprintf("%v", respValueOrig.Data["test22-key"])

		// Update deterministic key material to different value
		keyMaterialUpdate := "EkCXhcXHvfUMj8DWgWjfnxyWFz3GcOw8G1xB2PTcfPdbl93idxHTcmANzYLYW3KmsU0putTRfi3vxySALhSHaHl0"
		ids := []string{"97978150"}
		var reconstructedKey string
		var str string
		for _, id := range ids {
			upData := map[string]interface{}{
				"test22-key": make(map[string]interface{}),
			}
			upData["test22-key"].(map[string]interface{})[id] = keyMaterialUpdate

			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Storage:   storage,
				Operation: logical.UpdateOperation,
				Path:      "updateKeyMaterial",
				Data:      upData,
			})

			if err != nil {
				t.Fatal("updateKeyMaterial", err)
			}

			if len(resp.Data) == 0 {
				t.Fatal("updateKeyMaterial - no data returned")
			}
			str = fmt.Sprintf("%s", resp.Data["test22-key"])
			if str == "failed to update the material" {
				t.Errorf("updateKeyMaterial returned: %s", str)
				t.FailNow()
			}
			reconstructedKey = strings.Replace(str, "***", keyMaterialUpdate, -1)

		}

		// patch the masked result with the updated value

		// decrypt with reconstructed json key
		kh, _ := insecurecleartextkeyset.Read(keyset.NewJSONReader(bytes.NewBufferString(reconstructedKey)))
		d, err := daead.New(kh)
		if err != nil {
			log.Fatal(err)
		}

		// encrypt original data using key with patched material
		aad := []byte("test22-key")
		msg := []byte(data["test22-key"].(string))
		ct, err := d.EncryptDeterministically([]byte(msg), aad)
		if err != nil {
			log.Fatal(err)
		}
		expectedEncryptedValue := b64.StdEncoding.EncodeToString(ct)

		// value encrypted with key that was change needs to be different than original encrypted value
		if expectedEncryptedValue == valueEncryptedWithOriginalKey {
			t.Errorf("expected %q to be diferent to %q", valueEncryptedWithOriginalKey, expectedEncryptedValue)
		}

		// encrypt data
		// encrypt data on the server using new patched key
		respValue := encryptData(b, storage, data, t)
		valueEncryptedWithReconstructedKey := fmt.Sprintf("%v", respValue.Data["test22-key"])
		if expectedEncryptedValue != valueEncryptedWithReconstructedKey {
			t.Errorf("expected %q to be %q", valueEncryptedWithReconstructedKey, expectedEncryptedValue)
		}
		// decrypted result should match expectation
		respValueDec := decryptData(b, storage, respValue, t)
		valueDecrypted := fmt.Sprintf("%v", respValueDec.Data["test22-key"])
		if valueDecrypted != data["test22-key"] {
			t.Errorf("expected %q to be %q", valueDecrypted, data["test22-key"])
		}

		if strings.Count(str, "***") != 6 {
			t.Errorf("material was not changed %s", str)
		}

	})

	t.Run("test23 pathUpdateKeyID non-deterministic", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

		keyData := make(map[string]interface{})
		keyData["test23-key"] = NonDeterministicKeyset

		keyResp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "importKey",
			Data:      keyData,
		})

		if err != nil {
			t.Fatal("importKey", err)
		}

		if len(keyResp.Data) == 0 {
			t.Fatal("importKey - no data returned")

		}

		keyMap := map[string]interface{}{
			"test23-key": "gcm/test23-key",
		}
		// store the config
		saveConfig(b, storage, keyMap, false, t)

		updData := make(map[string]interface{})
		upDataInner := make(map[string]interface{})
		upDataInner["3192631270"] = "3192631271"
		updData["test23-key"] = upDataInner

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "updateKeyID",
			Data:      updData,
		})

		if err != nil {
			t.Fatal("updateKeyID", err)
		}

		if len(resp.Data) == 0 {
			t.Fatal("updateKeyID - no data returned")
		}

		str := fmt.Sprintf("%s", resp.Data)
		if !strings.Contains(str, "primaryKeyId\":3192631271") {
			t.Errorf("primary id  not changed %s", str)
		}

		if strings.Contains(str, "3192631270") {
			t.Errorf("original id  not changed %s", str)
		}
	})

	t.Run("test24 pathUpdatePrimaryKeyID deterministic", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

		keyData := make(map[string]interface{})
		keyData["test24-key"] = DeterministicKeyset

		keyResp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "importKey",
			Data:      keyData,
		})

		if err != nil {
			t.Fatal("importKey", err)
		}

		if len(keyResp.Data) == 0 {
			t.Fatal("importKey - no data returned")
		}
		keyMap := map[string]interface{}{
			"test24-key": "siv/test24-key",
		}
		// store the config
		saveConfig(b, storage, keyMap, false, t)
		updData := make(map[string]interface{})
		updData["test24-key"] = "2568362933"

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "updatePrimaryKeyID",
			Data:      updData,
		})

		if err != nil {
			t.Fatal("updateKeyID", err)
		}

		if len(resp.Data) == 0 {
			t.Fatal("updateKeyID - no data returned")
		}

		str := fmt.Sprintf("%s", resp.Data)
		if !strings.Contains(str, "primaryKeyId\":2568362933") {
			t.Errorf("primary id  not changed %s", str)
		}

	})

	t.Run("test25 pathImportKey", func(t *testing.T) {
		b, storage := testBackend(t)

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

		keyData := make(map[string]interface{})
		keyData["test25-key"] = DeterministicKeyset

		keyResp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "importKey",
			Data:      keyData,
		})

		if err != nil {
			t.Fatal("importKey", err)
		}

		if len(keyResp.Data) == 0 {
			t.Fatal("importKey - no data returned")
		}

	})

	t.Run("test26 set AD", func(t *testing.T) {
		b, storage := testBackend(t)

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

		// create a key
		keyData := make(map[string]interface{})
		keyData["test26-key"] = DeterministicKeyset

		keyResp, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "importKey",
			Data:      keyData,
		})

		if err != nil {
			t.Fatal("importKey", err)
		}

		if len(keyResp.Data) == 0 {
			t.Fatal("importKey - no data returned")
		}

		keyMap := map[string]interface{}{
			"test26-key": "siv/test26-key",
		}
		// store the config
		saveConfig(b, storage, keyMap, false, t)

		// encrypt something, save the encrypted value
		dataForEncryption := map[string]interface{}{
			"test26-key": "something",
		}
		// encrypt the data
		respEncrpt1 := encryptData(b, storage, dataForEncryption, t)
		respEncrpt2 := encryptData(b, storage, dataForEncryption, t)

		// set an AD for test26-key
		configADData := map[string]interface{}{
			"ADDITIONAL_DATA_test26-key": "newadditionaldata",
		}

		saveConfig(b, storage, configADData, false, t)

		respEncrpt3 := encryptData(b, storage, dataForEncryption, t)

		if fmt.Sprintf("%s", respEncrpt1.Data["test26-key"]) != fmt.Sprintf("%s", respEncrpt2.Data["test26-key"]) {
			t.Error("the first 2 encrypted values should be the same as additional data did not change")
		}
		if fmt.Sprintf("%s", respEncrpt1.Data["test26-key"]) == fmt.Sprintf("%s", respEncrpt3.Data["test26-key"]) {
			t.Error("the third 2 encrypted values should be different as additional data did change")
		}
	})

	t.Run("test27 set key family", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "config",
			Data:      map[string]interface{}{"test27-address": "ADDRESS_FAMILY", "test27-phone": "ADDRESS_FAMILY"},
		})
		if err != nil {
			t.Fatal("saveConfig", err)
		}
		// set some data to be encrypted using the keys
		familySetup := map[string]interface{}{
			"ADDRESS_FAMILY": DeterministicKeyset,
		}

		_, err = b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "importKey",
			Data:      familySetup,
		})
		if err != nil {
			t.Fatal("saveConfig", err)
		}

		keyMap := map[string]interface{}{
			"ADDRESS_FAMILY": "siv/ADDRESS_FAMILY",
		}
		// store the config
		saveConfig(b, storage, keyMap, false, t)

		// storeKeyValue("test27-address2", "ADDRESS_FAMILY", t)
		// storeKeyValue("test27-phone2", "ADDRESS_FAMILY", t)
		// saveConfig(b, storage, , false, t)

		// retreive the encrypted data for field address
		// actualEncryptedValue := fmt.Sprintf("%v", resp.Data["ADDRESS_FAMILY"]) // convert the cyphertext (=interface{}) received to a string

		// // get the actual Json key used from teh config for address
		// actualJSonKey4Phone := configResp.Data["test27-address2"].(string)
		// actualJSonKey4Address := configResp.Data["test27-address2"].(string)
		// actualJSonKey4Family := configResp.Data["ADDRESS_FAMILY"].(string)

		// // re-encrypt the data using the same key
		_, d, err := aeadutils.CreateInsecureHandleAndDeterministicAead(DeterministicKeyset)
		if err != nil {
			log.Fatal(err)
		}

		// expected
		data := map[string]interface{}{
			"test27-address": "my address",
			"test27-phone":   "my phone",
			"ADDRESS_FAMILY": "This will encrypt as well",
		}
		for k, v := range data {
			// fmt.Printf("\n ---\n ^^^\n %s %s", k, v.(string))
			ct, err := d.EncryptDeterministically([]byte(v.(string)), []byte(k))
			if err != nil {
				log.Fatal(err)
			}

			// fmt.Printf("\n ---\n ^^^\n ")
			expectedEncryptedValue := b64.StdEncoding.EncodeToString(ct)
			// fmt.Printf("\n ---\n ^^^\n   %s\n   %s\n   %s\n", k, v.(string), expectedEncryptedValue)
			actualEncryptedValue := encryptData(b, storage, map[string]interface{}{k: v}, t)

			assertEqual(actualEncryptedValue.Data[k].(string), expectedEncryptedValue, t)

		}

	})

	t.Run("testkv1 ckv read", func(t *testing.T) {

		// t.Parallel()
		b, storage := testBackend(t)

		if vault_kv_active == "false" {
			t.SkipNow()
		}

		resp := readKV(b, storage, t)

		if resp == nil || resp.Data == nil {
			t.Error("nothing returned from KV")
		}
	})

	t.Run("testkv2 kv sync", func(t *testing.T) {

		b, storage := testBackend(t)

		if vault_kv_active == "false" {
			t.SkipNow()
		}

		configMap := createVaultConfig()

		// store the config
		saveConfig(b, storage, configMap, false, t)

		// create a dynamic AEAD key for a field
		// set some data to be encrypted using the keys
		data := map[string]interface{}{
			"testkv2-address": "my address",
		}

		// create a key - should get synced as gcm/testkv2-address
		encryptDataNonDetermisticallyAndCreateKey(b, storage, data, false, t)

		resp := readKV(b, storage, t)

		_, ok := resp.Data["gcm/testkv2-address"]
		if !ok {
			t.Error("did not find entry for gcm/testkv2-address")
		}

		// OK its in KV and it looks ok, lets double -check the format by reading kv directly

		// check kv secret
		fullName := "gcm/testkv2-address"

		checkKVSecret(fullName, t)

		// create a key - should get synced as gcm/testkv2-address
		encryptDataDetermisticallyAndCreateKey(b, storage, data, false, t)

		resp = readKV(b, storage, t)

		_, ok = resp.Data["siv/testkv2-address"]
		if !ok {
			t.Error("did not find entry for siv/testkv2-address")
		}

		// OK its in KV and it looks ok, lets double -check the format by reading kv directly

		// check kv secret
		fullName = "siv/testkv2-address"

		checkKVSecret(fullName, t)
	})

}

func TestBQ(t *testing.T) {

	// un comment this if you need to debug bqsync
	t.Run("test-bqsync fake test to debug bqsync ", func(t *testing.T) {

		if bq_active == "false" {
			t.SkipNow()
		}

		// t.Parallel()
		b, storage := testBackend(t)

		configMap := map[string]interface{}{

			"BQ_KMSKEY":                  "projects/vf-cis-rubik-tst-kms/locations/<region>/keyRings/hsm-key-tink-pf1-<region>/cryptoKeys/bq-key",
			"BQ_PROJECT":                 "vf-pf1-datahub-b14b",
			"BQ_DEFAULT_ENCRYPT_DATASET": "vfpf1_dh_lake_aead_encrypt_<region>_lv_s",
			"BQ_DEFAULT_DECRYPT_DATASET": "vfpf1_dh_lake_<category>_aead_decrypt_<region>_lv_s",
			"BQ_ROUTINE_DET_PREFIX":      "siv",
			"BQ_ROUTINE_NONDET_PREFIX":   "gcm",
		}
		// store the config
		saveConfig(b, storage, configMap, false, t)

		key := "testbqsync-address"
		value := "my address"

		nondetkey := map[string]interface{}{
			key: value,
		}

		encryptDataNonDetermisticallyAndCreateKey(b, storage, nondetkey, false, t)

		key = "testbqsync-postcode"
		value = "my postcode"
		key1 := "name"
		value1 := "my name"

		detkey := map[string]interface{}{
			key:  value,
			key1: value1,
		}

		encryptDataDetermisticallyAndCreateKey(b, storage, detkey, false, t)

		data := make(map[string]interface{})

		tn := time.Now()

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "bqsync",
			Data:      data,
		})
		if err != nil {
			t.Fatal("bqsync", err)
		}

		projectId := "vf-pf1-datahub-b14b"
		datasetName := "vfpf1_dh_lake_aead_encrypt_eu_lv_s"
		routineName := "testbqsync_postcode_siv_encrypt"
		checkBQRoutine(projectId, t, datasetName, routineName, tn)
	})

}

func checkBQRoutine(projectId string, t *testing.T, datasetName string, routineName string, tn time.Time) {
	ctx := context.Background()
	bigqueryClient, err := bigquery.NewClient(ctx, projectId)
	if err != nil {
		t.Fatal("Failed to create a bigquery client: " + err.Error())

	}
	defer bigqueryClient.Close()
	routineEncryptRef := bigqueryClient.Dataset(datasetName).Routine(routineName)
	var rm *bigquery.RoutineMetadata
	rm, err = routineEncryptRef.Metadata(ctx)
	if err != nil {
		t.Fatal("Failed to find routine: " + datasetName + ":" + routineName + ": " + err.Error())
	}
	if tn.After(rm.LastModifiedTime) {
		t.Error(datasetName + ":" + routineName + " did not change")
	} else {
		t.Log(datasetName + ":" + routineName + " did change")
	}
}

// func TestKV(t *testing.T) {

// t.Run("testkv1 ckv read", func(t *testing.T) {

// 	if vault_kv_active == "false" {
// 		t.SkipNow()
// 	}

// 	// t.Parallel()
// 	b, storage := testBackend(t)

// 	resp := readKV(b, storage, t)

// 	if resp == nil || resp.Data == nil {
// 		t.Error("nothing returned from KV")
// 	}
// })

// t.Run("testkv2 kv sync", func(t *testing.T) {

// 	if vault_kv_active == "false" {
// 		t.SkipNow()
// 	}

// 	b, storage := testBackend(t)

// 	configMap := createVaultConfig()

// 	// store the config
// 	saveConfig(b, storage, configMap, false, t)

// 	// create a dynamic AEAD key for a field
// 	// set some data to be encrypted using the keys
// 	data := map[string]interface{}{
// 		"testkv2-address": "my address",
// 	}

// 	// create a key - should get synced as gcm/testkv2-address
// 	encryptDataNonDetermisticallyAndCreateKey(b, storage, data, false, t)

// 	resp := readKV(b, storage, t)

// 	_, ok := resp.Data["gcm/testkv2-address"]
// 	if !ok {
// 		t.Error("did not find entry for gcm/testkv2-address")
// 	}

// 	// OK its in KV and it looks ok, lets double -check the format by reading kv directly

// 	// check kv secret
// 	fullName := "gcm/testkv2-address"

// 	checkKVSecret(fullName, t)

// 	// create a key - should get synced as gcm/testkv2-address
// 	encryptDataDetermisticallyAndCreateKey(b, storage, data, false, t)

// 	resp = readKV(b, storage, t)

// 	_, ok = resp.Data["siv/testkv2-address"]
// 	if !ok {
// 		t.Error("did not find entry for siv/testkv2-address")
// 	}

// 	// OK its in KV and it looks ok, lets double -check the format by reading kv directly

// 	// check kv secret
// 	fullName = "siv/testkv2-address"

// 	checkKVSecret(fullName, t)

//		})
//	}
func unwrapKeyset(transiturl string, keyStr string) (*keyset.Handle, error) {

	var kvOptions kvutils.KVOptions
	err := resolveKvOptions(&kvOptions)
	if err != nil {
		fmt.Printf("\nfailed to read vault config")
	}
	client, err := kvutils.KvGetClientWithApprole(kvOptions.Vault_transit_url, kvOptions.Vault_transit_namespace, kvOptions.Vault_transit_approle_id, kvOptions.Vault_transit_secret_id, kvOptions.Vault_kv_writer_role, kvOptions.Vault_secretgenerator_iam_role)
	var vaultWrapper kvutils.VaultClientWrapper = kvutils.VaultClientWrapperImpl{Client: client.WithNamespace(kvOptions.Vault_transit_namespace)}
	base64Keyset, err := kvutils.UnwrapKeyset(&vaultWrapper, kvutils.EncryptedKVKey{Ciphertext: keyStr}, kvOptions.Vault_transit_kek, kvOptions.Vault_transit_engine)
	if err != nil {
		fmt.Printf("failed to unwrap key")
	}
	keysetByte, _ := b64.StdEncoding.DecodeString(base64Keyset)
	keysetStr := string(keysetByte)
	// validate the key
	kh, err := aeadutils.ValidateKeySetJson(keysetStr)
	if err != nil {
		log.Fatal(err)
	}

	ksi := kh.KeysetInfo()
	ki := ksi.KeyInfo[len(ksi.KeyInfo)-1]
	keyTypeURL := ki.GetTypeUrl()
	if keyTypeURL == "" {
		return nil, fmt.Errorf("failed to determine the keyType")
	}

	return kh, nil
}

func checkKVSecret(fullName string, t *testing.T) {
	fieldName := aeadutils.RemoveKeyPrefix(fullName)

	client, err := kvutils.KvGetClientWithApprole(vault_kv_url, "", vault_kv_approle_id, vault_kv_secret_id, vault_kv_writer_role, vault_secretgenerator_iam_role)
	if err != nil {
		t.Error("\nfailed to initialize Vault client")
	}

	kvsecret, err := kvutils.KvGetSecret(client, vault_kv_engine, vault_kv_version, fullName)
	if err != nil {
		t.Errorf("failed to read the secrets in folder %s: %s", fullName, err)
	}

	if kvsecret == nil {
		t.Errorf("failed to read the secrets in folder %s: secret not found", fullName)
	}

	if kvsecret.Data == nil {
		t.Errorf("failed to read the secrets in folder %s: data not found", fullName)
	}

	jsonKey, ok := kvsecret.Data["data"]
	if !ok {
		t.Errorf("failed to read back the aead key  %v", fullName)
	}
	secretStr := fmt.Sprintf("%v", jsonKey)
	var jMap map[string]aeadutils.KeySetStruct
	if err := json.Unmarshal([]byte(secretStr), &jMap); err != nil {
		t.Errorf("failed to unmarshall the secret  %v", fullName)
	}
	keysetAsMap := jMap[fieldName]
	keysetAsByteArray, err := json.Marshal(keysetAsMap)
	if err != nil {
		t.Error("failed to marshall ")
	}
	jsonToValidate := string(keysetAsByteArray)
	_, err = aeadutils.ValidateKeySetJson(jsonToValidate)
	if err != nil {
		t.Errorf("failed to recreate a key handle from the json for  %v", fullName)
	}

	jsonAad, ok := kvsecret.Data["aad"]
	if !ok {
		t.Errorf("failed to read back the aead aad  %v", fullName)
	}
	secretStr = fmt.Sprintf("%v", jsonAad)
	var jMapAad map[string]interface{}
	if err := json.Unmarshal([]byte(secretStr), &jMapAad); err != nil {
		t.Errorf("failed to unmarshall the secret aad  %v", fullName)
	}
	jMapAadValue, ok := jMapAad[fieldName]
	if !ok {
		t.Error("failed to find aad value")
	}
	jMapAadValueStr := fmt.Sprintf("%v", jMapAadValue)
	if jMapAadValueStr != fieldName {
		t.Error("aad value is incorrect")
	}
}

func checkKVTransitWrappedSecret(fullName string, t *testing.T) {

	client, err := kvutils.KvGetClientWithApprole(vault_transit_url, vault_transit_namespace, vault_transit_kv_approle_id, vault_transit_kv_secret_id, vault_kv_writer_role, vault_secretgenerator_iam_role)
	if err != nil {
		t.Error("\nfailed to initialize Vault client")
	}

	var kvsecret *vault.KVSecret

	if vault_transit_namespace != "" {
		kvsecret, err = kvutils.KvGetSecret(client.WithNamespace(vault_transit_namespace), vault_transit_kv_engine, vault_transit_kv_version, fullName)
	} else {
		kvsecret, err = kvutils.KvGetSecret(client, vault_transit_kv_engine, vault_transit_kv_version, fullName)
	}
	if err != nil || kvsecret.Data == nil {
		t.Errorf("failed to read the secrets in folder %v", fullName)
	}

	wrappedKeyIntf, ok := kvsecret.Data["key"]
	if !ok {
		t.Errorf("failed to read back the wrapped aead key  %v", fullName)
	}

	wrappedKeyStr := fmt.Sprintf("%v", wrappedKeyIntf)

	if vault_transit_namespace == "" {
		// ${VAULT_SERVER}/v1/kms/${LM}/${LM}_transit/decrypt/${LM}_KEK
		_, err = unwrapKeyset(vault_transit_url+"/v1/"+vault_transit_engine+"/decrypt/"+vault_transit_kek, wrappedKeyStr)
	} else {
		_, err = unwrapKeyset(vault_transit_url+"/v1/"+vault_transit_namespace+"/"+vault_transit_engine+"/decrypt/"+vault_transit_kek, wrappedKeyStr)
	}

	if err != nil {
		t.Error("failed to unwrap keyset and confirm type of aead key")
	}

}
func TestTransitKV(t *testing.T) {

	t.Run("testtransitkv1 transit kv sync", func(t *testing.T) {
		// t.Parallel()
		b, storage := testBackend(t)

		if vault_transit_active == "false" {
			t.SkipNow()
		}

		configMap := createVaultConfig()

		// store the config and create 3 keys
		saveConfig(b, storage, configMap, true, t)
		// set up config (sync to transit = false)

		keyMap := map[string]interface{}{
			"gcm/test30-key1": NonDeterministicKeyset,
			"gcm/test30-key2": NonDeterministicKeyset,
			"gcm/test30-key3": NonDeterministicKeyset,
		}
		saveConfig(b, storage, keyMap, true, t)

		// set up config (sync to transit = true)
		newMap := map[string]interface{}{
			"VAULT_TRANSIT_ACTIVE": "true",
		}
		saveConfig(b, storage, newMap, true, t)

		syncMap := map[string]interface{}{
			"gcm/test30-key1": "true",
			"gcm/test30-key2": "false",
			"gcm/test30-key3": "true",
		}

		// sync 2 of them
		resp := syncTransitKV(b, storage, syncMap, t)

		for k, v := range resp.Data {
			fmt.Printf("\nresp-k=%v resp-v=%v", k, v)

		}

		// we should have a wrapped secret in kv called XXX_DEK_TEST30-KEY1_AES256_GCM
		ns := "XXX"
		if vault_transit_namespace != "" && strings.Contains(vault_transit_namespace, "kms/") {
			ns = strings.ToUpper(strings.TrimPrefix(vault_transit_namespace, "kms/"))
		}
		checkKVTransitWrappedSecret(ns+"_DEK_TEST30-KEY1_AES256_GCM", t)
		checkKVTransitWrappedSecret(ns+"_DEK_TEST30-KEY3_AES256_GCM", t)

	})
}

func assertEqual(str1 string, str2 string, t *testing.T) {
	if !(str1 == str2) {
		t.Errorf("expected %q to be %q", str1, str2)
	}
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

func readKV(b *backend, storage logical.Storage, t *testing.T) *logical.Response {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "readkv",
	})
	if err != nil {
		t.Fatal("readkv", err)
	}
	return resp
}

func syncKV(b *backend, storage logical.Storage, t *testing.T) *logical.Response {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.ReadOperation,
		Path:      "synckv",
	})
	if err != nil {
		t.Fatal("synckv", err)
	}
	return resp
}

func syncTransitKV(b *backend, storage logical.Storage, data map[string]interface{}, t *testing.T) *logical.Response {

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "synctransitkv",
		Data:      data,
	})
	if err != nil {
		t.Fatal("synctransitkv", err)
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

func createVaultConfig() map[string]interface{} {
	configMap := map[string]interface{}{
		"VAULT_KV_ACTIVE":                   vault_kv_active,
		"VAULT_KV_URL":                      vault_kv_url,
		"VAULT_KV_ENGINE":                   vault_kv_engine,
		"VAULT_KV_VERSION":                  vault_kv_version,
		"VAULT_KV_APPROLE_ID":               vault_kv_approle_id,
		"VAULT_KV_SECRET_ID":                vault_kv_secret_id,
		"VAULT_TRANSIT_ACTIVE":              vault_transit_active,
		"VAULT_TRANSIT_URL":                 vault_transit_url,
		"VAULT_TRANSIT_APPROLE_ID":          vault_transit_kv_approle_id,
		"VAULT_TRANSIT_SECRET_ID":           vault_transit_kv_secret_id,
		"VAULT_TRANSIT_KV_ENGINE":           vault_transit_kv_engine,
		"VAULT_TRANSIT_KV_VERSION":          vault_transit_kv_version,
		"VAULT_TRANSIT_NAMESPACE":           vault_transit_namespace,
		"VAULT_TRANSIT_ENGINE":              vault_transit_engine,
		"VAULT_TRANSIT_KEK":                 vault_transit_kek,
		"VAULT_KV_WRITER_ROLE":              vault_kv_writer_role,
		"VAULT_KV_SECRETGENERATOR_IAM_ROLE": vault_secretgenerator_iam_role,
	}
	return configMap

}
