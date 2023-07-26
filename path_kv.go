package aeadplugin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathSyncTransitKV(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	rtnMap := make(map[string]interface{})

	var kvOptions KVOptions
	err := resolveKvOptions(&kvOptions)
	if err != nil {
		hclog.L().Error("\nfailed to read vault config")
		return nil, err
	}

	if kvOptions.vault_kv_active == "true" {

		// get all the keys in KV
		kvMap, err := b.readKV(ctx, req.Storage, false)

		if err != nil || kvMap == nil {
			rtnMap["Error"] = err.Error()
		} else {

			for keyName, v := range data.Raw {
				if "true" == fmt.Sprintf("%s", v) {
					jsonIntf, ok := kvMap[keyName]
					if !ok {
						rtnMap[keyName] = "Error: key not found in KV: " + keyName
					} else {
						// ok we have the key in KV, lets extract the json as a string and send it to transitkv
						keyJson := fmt.Sprint(jsonIntf)
						_, err := saveToTransitKV(RemoveKeyPrefix(keyName), keyJson)
						if err != nil {
							rtnMap[keyName] = "Error saving to transit: " + err.Error()
						}
					}
				}
			}
		}
	}
	return &logical.Response{
		Data: rtnMap,
	}, nil
}

func (b *backend) pathSyncKV(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	kvMap := map[string]interface{}{}
	rtnMap := make(map[string]interface{})

	var kvOptions KVOptions
	err := resolveKvOptions(&kvOptions)
	if err != nil {
		hclog.L().Error("\nfailed to read vault config")
		return nil, err
	}

	if kvOptions.vault_kv_active == "true" {

		kvMap, err = b.readKV(ctx, req.Storage, false)

		if err != nil {
			rtnMap["error"] = err.Error()
		} else {

			gcmcount := 0
			sivcount := 0
			aadcount := 0
			for k, _ := range kvMap {
				if strings.HasPrefix(k, "ADDITIONAL") {
					aadcount++
				} else if strings.HasPrefix(k, "gcm/") {
					gcmcount++
				} else if strings.HasPrefix(k, "siv/") {
					sivcount++
				}
			}

			rtnMap["ADDITIONAL DATA SYNCED"] = aadcount
			rtnMap["GCM KEYS SYNCED"] = gcmcount
			rtnMap["SIV KEYS SYNCED"] = sivcount

			data.Raw = kvMap
			if _, err := b.configWriteOverwriteCheck(ctx, req, data, true, false); err != nil {
				return &logical.Response{
					Data: rtnMap,
				}, err
			}
		}
	}
	return &logical.Response{
		Data: rtnMap,
	}, nil
}

func (b *backend) pathReadKV(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	m := map[string]interface{}{}

	var kvOptions KVOptions
	err := resolveKvOptions(&kvOptions)
	if err != nil {
		hclog.L().Error("\nfailed to read vault config")
		return nil, err
	}

	if kvOptions.vault_kv_active == "true" {

		m, err = b.readKV(ctx, req.Storage)

		if err != nil {
			m = map[string]interface{}{}
			m["error"] = err.Error()
		}
	}
	return &logical.Response{
		Data: m,
	}, nil
}

func (b *backend) readKV(ctx context.Context, s logical.Storage, mask ...bool) (map[string]interface{}, error) {

	var kvOptions KVOptions
	err := resolveKvOptions(&kvOptions)
	if err != nil {
		hclog.L().Error("\nfailed to read vault config")
		return nil, err
	}

	if kvOptions.vault_kv_active == "false" {
		return nil, nil
	}
	// get a client
	client, err := KvGetClient(kvOptions.vault_kv_url, "", kvOptions.vault_kv_approle_id, kvOptions.vault_kv_secret_id)

	if err != nil {
		hclog.L().Error("\nfailed to initialize Vault client1")
		return nil, err
	}

	// we are looking for:
	// engine: kv_engine
	// path: gcm/addressline and siv/addressline
	// data and aad

	// read the paths
	paths, err := KvGetSecretPaths(client, kvOptions.vault_kv_engine, kvOptions.vault_kv_version, "")

	if err != nil || paths == nil {
		hclog.L().Error("failed to read paths")
	}
	consulKV := make(map[string]interface{})

	// iterate through the paths
	for _, path := range paths {
		keyFound := false
		if strings.HasPrefix(path, "gcm/") || strings.HasPrefix(path, "siv/") {
			kvsecret, err := KvGetSecret(client, kvOptions.vault_kv_engine, kvOptions.vault_kv_version, path)
			if err != nil || kvsecret.Data == nil {
				hclog.L().Error("failed to read the secrets in folder " + path)
			}

			keyFound = true

			jsonKey, ok := kvsecret.Data["data"]
			if !ok {
				hclog.L().Error("failed to read back the aead key " + path)
			}

			if extractedKeySet, err := isSecretAnAEADKeyset(jsonKey, path); err != nil {
				hclog.L().Error("failed to read vailid secret key " + path)
			} else {
				// hclog.L().Info("valid secret key")
				if mask == nil || mask[0] == true {
					consulKV[path] = muteKeyMaterial(extractedKeySet)
				} else {
					consulKV[path] = extractedKeySet
				}

			}

			jsonAad, ok := kvsecret.Data["aad"]
			if !ok {
				hclog.L().Error("failed to read back the aad key " + path)
			}
			if extractedAD, err := extractADFromSecret(jsonAad, path); err != nil {
				hclog.L().Error("failed to read vailid secret key " + path)
			} else {
				consulKV["ADDITIONAL_DATA-"+path] = extractedAD
			}
		}

		if !keyFound {
			hclog.L().Error("failed to read back the secret " + path)
		}

	}

	return consulKV, nil
}
func resolveKvOptions(kvOptions *KVOptions) error {

	kvOptions.vault_kv_active = "false" // default
	kv_active, ok := AEAD_CONFIG.Get("VAULT_KV_ACTIVE")
	if ok {
		kvOptions.vault_kv_active = fmt.Sprintf("%v", kv_active)
	}

	vault_url, ok := AEAD_CONFIG.Get("VAULT_KV_URL")
	if ok {
		kvOptions.vault_kv_url = fmt.Sprintf("%v", vault_url)
	}

	vault_approleid, ok := AEAD_CONFIG.Get("VAULT_KV_APPROLE_ID")
	if ok {
		kvOptions.vault_kv_approle_id = fmt.Sprintf("%v", vault_approleid)
	}

	vault_secretid, ok := AEAD_CONFIG.Get("VAULT_KV_SECRET_ID")
	if ok {
		kvOptions.vault_kv_secret_id = fmt.Sprintf("%v", vault_secretid)
	}

	kv_engine, ok := AEAD_CONFIG.Get("VAULT_KV_ENGINE")
	if ok {
		kvOptions.vault_kv_engine = fmt.Sprintf("%v", kv_engine)
	}

	kv_version, ok := AEAD_CONFIG.Get("VAULT_KV_VERSION")
	if ok {
		kvOptions.vault_kv_version = fmt.Sprintf("%v", kv_version)
	}

	kvOptions.vault_transit_active = "false" // default
	vault_transit_active, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_ACTIVE")
	if ok {
		kvOptions.vault_transit_active = fmt.Sprintf("%v", vault_transit_active)
	}
	vault_transit_url, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_URL")
	if ok {
		kvOptions.vault_transit_url = fmt.Sprintf("%v", vault_transit_url)
	}
	vault_transit_approle_id, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_APPROLE_ID")
	if ok {
		kvOptions.vault_transit_approle_id = fmt.Sprintf("%v", vault_transit_approle_id)
	}
	vault_transit_secret_id, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_SECRET_ID")
	if ok {
		kvOptions.vault_transit_secret_id = fmt.Sprintf("%v", vault_transit_secret_id)
	}
	vault_transit_kv_engine, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_KV_ENGINE")
	if ok {
		kvOptions.vault_transit_kv_engine = fmt.Sprintf("%v", vault_transit_kv_engine)
	}
	vault_transit_engine, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_ENGINE")
	if ok {
		kvOptions.vault_transit_engine = fmt.Sprintf("%v", vault_transit_engine)
	}
	vault_transit_kv_version, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_KV_VERSION")
	if ok {
		kvOptions.vault_transit_kv_version = fmt.Sprintf("%v", vault_transit_kv_version)
	}
	vault_transit_namespace, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_NAMESPACE")
	if ok {
		kvOptions.vault_transit_namespace = fmt.Sprintf("%v", vault_transit_namespace)
	}
	vault_transit_tokenname, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_TOKENNAME")
	if ok {
		kvOptions.vault_transit_tokenname = fmt.Sprintf("%v", vault_transit_tokenname)
	}
	vault_transit_kek, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_KEK")
	if ok {
		kvOptions.vault_transit_kek = fmt.Sprintf("%v", vault_transit_kek)
	}

	return nil
}
func saveToKV(keyNameIn string, keyJsonIn interface{}) (bool, error) {

	var kvOptions KVOptions
	err := resolveKvOptions(&kvOptions)
	if err != nil {
		hclog.L().Error("\nfailed to read vault config")
		return false, err
	}

	if kvOptions.vault_kv_active == "false" {
		return true, nil
	}

	potentialAEADKey := fmt.Sprintf("%v", keyJsonIn)
	if potentialAEADKey == "" {
		return true, nil
	}

	kh, err := ValidateKeySetJson(potentialAEADKey)
	if err != nil {
		return true, nil
	}

	ksi := kh.KeysetInfo()
	ki := ksi.KeyInfo[len(ksi.KeyInfo)-1]
	keyTypeURL := ki.GetTypeUrl()

	hclog.L().Info("saveToKV:" + keyNameIn + " Type: " + keyTypeURL)

	// get a client
	client, err := KvGetClient(kvOptions.vault_kv_url, "", kvOptions.vault_kv_approle_id, kvOptions.vault_kv_secret_id)
	if err != nil {
		hclog.L().Error("\nfailed to initialize Vault client2")
		return false, err
	}

	// // create a secret
	keyMap := make(map[string]interface{})
	keyMap[RemoveKeyPrefix(keyNameIn)] = keyJsonIn
	// Marshal the map into a JSON string.
	keyData, err := json.Marshal(keyMap)
	if err != nil {
		fmt.Println(err.Error())
	}
	jsonKeyStr := string(keyData)

	aadMap := make(map[string]interface{})
	aadMap[RemoveKeyPrefix(keyNameIn)] = RemoveKeyPrefix(keyNameIn)
	// Marshal the map into a JSON string.
	aadData, err := json.Marshal(aadMap)
	if err != nil {
		fmt.Println(err.Error())
	}

	jsonAadStr := string(aadData)

	// secretMap["aad"] = aadMap
	secretMap := make(map[string]interface{})

	secretMap["data"] = jsonKeyStr
	secretMap["aad"] = jsonAadStr

	/*
				{"aad":"{\"mykey\":\"mykey\"}","data":"{\"mykey\":\"{\\\"primaryKeyId\\\":42267057,\\\"key\\\":[{\\\"keyData\\\":{\\\"typeUrl\\\":\\\"type.googleapis.com/google.crypto.tink.AesSivKey\\\",\\\"value\\\":\\\"EkDAEgACCd1/yruZMuI49Eig5Glb5koi0DXgx1mXVALYJWNRn5wYuQR46ggNuMhFfhrJCsddVp/Q7Pot2hvHoaQS\\\",\\\"keyMaterialType\\\":\\\"SYMMETRIC\\\"},\\\"status\\\":\\\"ENABLED\\\",\\\"keyId\\\":42267057,\\\"outputPrefixType\\\":\\\"TINK\\\"}]}\"}"}
						TARGET
						{
						"aad": "{ \"addressline\": \"addressline\"}",
						"data": "{ \"addressline\": {\"primaryKeyId\":2908092989,\"key\":[{\"keyData\":{\"typeUrl\":\"type.googleapis.com/google.crypto.tink.AesGcmKey\",\"value\":\"GiCxL6bcfqhToSRj+O6eiFcGdKUthjAIZGgKB3u/Vdwwag==\",\"keyMaterialType\":\"SYMMETRIC\"},\"status\":\"ENABLED\",\"keyId\":2908092989,\"outputPrefixType\":\"TINK\"}]} }"
						}
						ACTUAL
						{
						"aad": "{\"aeadkeyset1\":\"aeadkeyset1\"}",
						"data": "{\"aeadkeyset1\":\"{\\\"primaryKeyId\\\":330204194, \\\"key\\\":[{\\\"keyData\\\":{\\\"typeUrl\\\":\\\"type.googleapis.com/google.crypto.tink.AesGcmKey\\\", \\\"value\\\":\\\"GiBa0wZ4ACjtW137qTVSY2ofQBCffdzkzhNkktlMtDFazA==\\\", \\\"keyMaterialType\\\":\\\"SYMMETRIC\\\"}, \\\"status\\\":\\\"ENABLED\\\", \\\"keyId\\\":1416257722, \\\"outputPrefixType\\\":\\\"TINK\\\"}, {\\\"keyData\\\":{\\\"typeUrl\\\":\\\"type.googleapis.com/google.crypto.tink.AesGcmKey\\\", \\\"value\\\":\\\"GiC+RkZ/ar1mFOD0QhxXk5Cg1x8ni0b89bXi1BOfz00EXg==\\\", \\\"keyMaterialType\\\":\\\"SYMMETRIC\\\"}, \\\"status\\\":\\\"ENABLED\\\", \\\"keyId\\\":330204194, \\\"outputPrefixType\\\":\\\"TINK\\\"}]}\"}"
						}
		}
	*/
	kv_engineInf, ok := AEAD_CONFIG.Get("VAULT_KV_ENGINE")
	kv_engine := "secret" // default
	if ok {
		kv_engine = fmt.Sprintf("%v", kv_engineInf)
	}

	kv_versionInf, ok := AEAD_CONFIG.Get("VAULT_KV_VERSION")
	kv_version := "v2" // default
	if ok {
		kv_version = fmt.Sprintf("%v", kv_versionInf)
	}

	_, err = KvPutSecret(client, kv_engine, kv_version, keyNameIn, secretMap)
	if err != nil {
		hclog.L().Error("failed to put a secret to KV")
		return false, err
	}

	kvsecret, err := KvGetSecret(client, kv_engine, kv_version, keyNameIn)
	if err != nil || kvsecret.Data == nil {
		hclog.L().Error("failed to read the secrets in folder:" + keyNameIn)
		return false, err
	}

	secret, ok := kvsecret.Data["data"]
	if !ok {
		hclog.L().Error("failed to extract the data from the secrets in folder:" + keyNameIn)
	}

	if _, err := isSecretAnAEADKeyset(secret, RemoveKeyPrefix(keyNameIn)); err != nil {
		return false, err
	}
	_, err = saveToTransitKV(RemoveKeyPrefix(keyNameIn), fmt.Sprintf("%s", keyJsonIn))
	if err != nil {
		return false, err
	}
	return true, nil
}

func saveToTransitKV(keyname string, keyjson string) (bool, error) {
	/*
	   // get the wrapped key
	   ```
	   curl -k --header "X-Vault-Token:${TOKEN}" --request GET ${VAULT_SERVER}/v1/kms/${LM}/${LM}_secrets/data/${LM}_DEK_${FIELD}_${KEYTYPE} -x ${PROXY} > ${FILE}_encrypted_dek.json
	   ```

	   // manipulate the wrapped key
	   ```
	   cat ${FILE}_encrypted_dek.json | jq '.' | grep key | awk -F"\"" '{print $4}' > tmp_${FILE}_encrypted_dek.json

	   echo "{" > ${FILE}_to_decrypt.json
	   echo "  \"ciphertext\": \"$(cat tmp_${FILE}_encrypted_dek.json)\"" >> ${FILE}_to_decrypt.json
	   echo "}" >> ${FILE}_to_decrypt.json
	   ```

	   // get the transit token - use client token to get it
	   ```
	   curl -k --header "X-Vault-Token:${TOKEN}" --request GET ${VAULT_SERVER}/v1/kms/${LM}/${LM}_secrets/data/nekoT-tisnarT_TI -x ${PROXY} > transit-token.txt
	   cat transit-token.txt | jq .data.data.key
	   export TOKEN=$(cat transit-token.txt | jq .data.data.key | sed 's/\"//g')
	   ```

	   // unwrap the key
	   ```
	   curl -k --header "X-Vault-Token:${TOKEN}" --request POST --data @${FILE}_to_decrypt.json ${VAULT_SERVER}/v1/kms/${LM}/${LM}_transit/decrypt/${LM}_KEK -x ${PROXY} | jq '.' | grep plaintext | awk -F"\"" '{print $4}' | base64 --decode > ${FILE}_decrypted.json
	   cat ${FILE}_decrypted.json | jq
	   ```
	*/

	var kvOptions KVOptions
	err := resolveKvOptions(&kvOptions)
	if err != nil {
		hclog.L().Error("\nfailed to read vault config")
		return false, err
	}

	if kvOptions.vault_transit_active == "false" {
		return true, nil
	}

	// get a client
	client, err := KvGetClient(kvOptions.vault_transit_url, kvOptions.vault_transit_namespace, kvOptions.vault_transit_approle_id, kvOptions.vault_transit_secret_id)
	if err != nil {
		hclog.L().Error("\nfailed to initialize Vault client3")
		return false, err
	}

	// read the secrets in the transit wrapped secret store
	keyStr := ""
	transitTokenStr := ""
	paths, err := KvGetSecretPaths(client.WithNamespace(kvOptions.vault_transit_namespace), kvOptions.vault_transit_kv_engine, kvOptions.vault_transit_kv_version, "")
	if err != nil {
		hclog.L().Error("failed to read paths")
	}
	for _, path := range paths {
		kvsecret, _ := KvGetSecret(client.WithNamespace(kvOptions.vault_transit_namespace), kvOptions.vault_transit_kv_engine, kvOptions.vault_transit_kv_version, path)
		secret, ok := kvsecret.Data["key"]
		if ok {
			if path == kvOptions.vault_transit_tokenname {
				transitTokenStr = fmt.Sprintf("%v", secret)
			}
		}
	}

	if transitTokenStr == keyStr {
		hclog.L().Error("oops")
	}

	// make a new keyname
	newkeyname, err := DeriveKeyName(kvOptions.vault_transit_namespace, keyname, keyjson)
	hclog.L().Info("newkeyname: " + newkeyname)

	//wrap the key

	url := kvOptions.vault_transit_url + "/v1/" + kvOptions.vault_transit_namespace + "/" + kvOptions.vault_transit_engine + "/encrypt/" + kvOptions.vault_transit_kek

	wrappedkey, err := WrapKeyset(url, transitTokenStr, keyjson)
	if err != nil {
		hclog.L().Error("failed to wrap key")
	}

	url = kvOptions.vault_transit_url + "/v1/" + kvOptions.vault_transit_namespace + "/" + kvOptions.vault_transit_engine + "/decrypt/" + kvOptions.vault_transit_kek
	_, err = UnwrapKeyset(url, transitTokenStr, wrappedkey)
	if err != nil {
		hclog.L().Error("failed to unwrap key")
	}

	secretMap := map[string]interface{}{}
	secretMap["key"] = wrappedkey
	_, err = KvPutSecret(client.WithNamespace(kvOptions.vault_transit_namespace), kvOptions.vault_transit_kv_engine, kvOptions.vault_transit_kv_version, newkeyname, secretMap)
	if err != nil {
		hclog.L().Error("failed to write to transit")
	}
	return true, nil
}

func isSecretAnAEADKeyset(secret interface{}, fName string) (string, error) {
	secretStr := fmt.Sprintf("%v", secret)
	fieldName := RemoveKeyPrefix(fName)
	var jMap map[string]interface{}
	if err := json.Unmarshal([]byte(secretStr), &jMap); err != nil {
		hclog.L().Error("failed to unmarshall the secret 'tmp/foo'")
		return "", err
	}

	jsonToValidate := fmt.Sprintf("%v", jMap[fieldName])
	if _, err := ValidateKeySetJson(jsonToValidate); err != nil {
		hclog.L().Error("failed to recreate a key handle from the json")
		return "", err
	}
	return jsonToValidate, nil
}

func extractADFromSecret(secret interface{}, fName string) (string, error) {
	secretStr := fmt.Sprintf("%v", secret)
	fieldName := RemoveKeyPrefix(fName)
	var jMap map[string]interface{}
	if err := json.Unmarshal([]byte(secretStr), &jMap); err != nil {
		hclog.L().Error("failed to unmarshall the secret 'tmp/foo'")
		return "", err
	}
	adStr := fmt.Sprintf("%v", jMap[fieldName])

	return adStr, nil
}

func deleteFromKV(k string) (bool, error) {
	hclog.L().Info("deleteFromKV:" + k)
	return true, nil
}
