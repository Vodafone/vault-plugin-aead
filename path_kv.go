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

func (b *backend) pathSyncKV(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	m, _ := b.readKV(ctx, req.Storage, false)

	gcmcount := 0
	sivcount := 0
	aadcount := 0
	for k, _ := range m {
		if strings.HasPrefix(k, "ADDITIONAL") {
			aadcount++
		} else if strings.HasPrefix(k, "gcm/") {
			gcmcount++
		} else if strings.HasPrefix(k, "siv/") {
			sivcount++
		}
	}

	rtnMap := make(map[string]interface{})
	rtnMap["ADDITIONAL DATA SYNCED"] = aadcount
	rtnMap["GCM KEYS SYNCED"] = gcmcount
	rtnMap["SIV KEYS SYNCED"] = sivcount

	data.Raw = m
	if _, err := b.configWriteOverwriteCheck(ctx, req, data, true, false); err != nil {
		return &logical.Response{
			Data: rtnMap,
		}, err
	}

	return &logical.Response{
		Data: rtnMap,
	}, nil
}

func (b *backend) pathReadKV(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	m, _ := b.readKV(ctx, req.Storage)

	return &logical.Response{
		Data: m,
	}, nil
}

func (b *backend) readKV(ctx context.Context, s logical.Storage, mask ...bool) (map[string]interface{}, error) {

	// get a client
	client, err := KvGetClient("VAULT_KV_URL", "", "VAULT_KV_APPROLE_ID", "VAULT_KV_SECRET_ID")
	if err != nil {
		hclog.L().Error("\nfailed to initialize Vault client1")
		return nil, err
	}

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

	// we are looking for:
	// engine: kv_engine
	// path: gcm/addressline and siv/addressline
	// data and aad

	// read the paths
	paths, err := KvGetSecretPaths(client, kv_engine, kv_version, "")
	if err != nil || paths == nil {
		hclog.L().Error("failed to read paths")
	}
	consulKV := make(map[string]interface{})

	// iterate through the paths
	for _, path := range paths {
		// hclog.L().Info("found path: " + path)
		keyFound := false
		if strings.HasPrefix(path, "gcm/") || strings.HasPrefix(path, "siv/") {
			kvsecret, err := KvGetSecret(client, kv_engine, kv_version, path)
			if err != nil || kvsecret.Data == nil {
				hclog.L().Error("failed to read the secrets in folder %s", path)
			}

			keyFound = true

			jsonKey, ok := kvsecret.Data["data"]
			if !ok {
				hclog.L().Error("failed to read back the aead key 'gcm/test4f1/data'")
			}
			// jsonKeyStr := fmt.Sprintf("%v", jsonKey)
			// hclog.L().Info("found jsonKeyStr: " + jsonKeyStr)
			if extractedKeySet, err := isSecretAnAEADKeyset(jsonKey, path); err != nil {
				hclog.L().Error("failed to read vailid secret key 'gcm/test4f1/aad'")
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
				hclog.L().Error("failed to read back the aad key 'gcm/test4f1/aad'")
			}
			if extractedAD, err := extractADFromSecret(jsonAad, path); err != nil {
				hclog.L().Error("failed to read vailid secret key 'gcm/test4f1/aad'")
			} else {
				consulKV["ADDITIONAL_DATA-"+path] = extractedAD
			}
			// hclog.L().Info("found jsonAadStr: " + jsonAadStr)

		}

		if !keyFound {
			hclog.L().Error("failed to read back the secret 'gcm/test4f1'")
		}

	}

	return consulKV, nil
}

func saveToKV(keyNameIn string, keyJsonIn interface{}) (bool, error) {

	kv_activeIntf, ok := AEAD_CONFIG.Get("VAULT_KV_ACTIVE")
	kv_active := "false" // default
	if ok {
		kv_active = fmt.Sprintf("%v", kv_activeIntf)
	}
	if kv_active == "false" {
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
	client, err := KvGetClient("VAULT_KV_URL", "", "VAULT_KV_APPROLE_ID", "VAULT_KV_SECRET_ID")
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

	// _, err = ValidateKeySetJson(jsonKeyStr)
	// if err != nil {
	// 	hclog.L().Error("failed to recreate a key handle from the json")
	// }

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
	saveToTransitKV(RemoveKeyPrefix(keyNameIn), fmt.Sprintf("%s", keyJsonIn))
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

	kv_activeIntf, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_ACTIVE")
	kv_active := "false" // default
	if ok {
		kv_active = fmt.Sprintf("%v", kv_activeIntf)
	}
	if kv_active == "false" {
		return true, nil
	}

	// get a client
	client, err := KvGetClient("VAULT_TRANSIT_URL", "kms/IT", "VAULT_TRANSIT_APPROLE_ID", "VAULT_TRANSIT_SECRET_ID")
	if err != nil {
		hclog.L().Error("\nfailed to initialize Vault client3")
		return false, err
	}

	// "VAULT_TRANSIT_KV_ENGINE":  vault_transit_kv_engine,
	// "VAULT_TRANSIT_NAMESPACE":  vault_transit_namespace,
	// "VAULT_TRANSIT_ENGINE":     vault_transit_engine,
	// "VAULT_TRANSIT_TOKENNAME":  vault_transit_tokenname,

	vault_transit_namespace := "" // default
	vault_transit_namespaceIntf, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_NAMESPACE")
	if ok {
		vault_transit_namespace = fmt.Sprintf("%v", vault_transit_namespaceIntf)
	}

	vault_transit_kv_engine := "" // default
	vault_transit_kv_engineIntf, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_KV_ENGINE")
	if ok {
		vault_transit_kv_engine = fmt.Sprintf("%v", vault_transit_kv_engineIntf)
	}

	vault_transit_engine := "" // default
	vault_transit_engineIntf, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_ENGINE")
	if ok {
		vault_transit_engine = fmt.Sprintf("%v", vault_transit_engineIntf)
	}
	kv_transit_versionInf, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_KV_VERSION")
	kv_transit_version := "v2" // default
	if ok {
		kv_transit_version = fmt.Sprintf("%v", kv_transit_versionInf)
	}

	vault_transit_tokenname := "" // default
	vault_transit_tokennameIntf, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_TOKENNAME")
	if ok {
		vault_transit_tokenname = fmt.Sprintf("%v", vault_transit_tokennameIntf)
	}

	if vault_transit_tokenname == vault_transit_engine {
		hclog.L().Error("failed to read paths")
	}
	// read the secrets in the transit wrapped secret store
	keyStr := ""
	transitTokenStr := ""
	paths, err := KvGetSecretPaths(client.WithNamespace(vault_transit_namespace), vault_transit_kv_engine, kv_transit_version, "")
	if err != nil {
		hclog.L().Error("failed to read paths")
	}
	for _, path := range paths {
		kvsecret, _ := KvGetSecret(client.WithNamespace(vault_transit_namespace), vault_transit_kv_engine, kv_transit_version, path)
		secret, ok := kvsecret.Data["key"]
		if ok {
			if path == vault_transit_tokenname {
				transitTokenStr = fmt.Sprintf("%v", secret)
			}
		}
	}

	if transitTokenStr == keyStr {
		hclog.L().Error("oops")
	}

	// make a new keyname
	newkeyname, err := DeriveKeyName("kms/IT", keyname, keyjson)
	hclog.L().Info("newkeyname: " + newkeyname)

	//wrap the key
	url := "https://poc2.vault.neuron.bdp.vodafone.com/v1/kms/IT/IT_transit/encrypt/IT_KEK"

	wrappedkey, _ := WrapKeyset(url, transitTokenStr, keyjson)

	UnwrapKeyset(url, transitTokenStr, wrappedkey)

	secretMap := map[string]interface{}{}
	secretMap["key"] = keyjson
	_, err = KvPutSecret(client.WithNamespace("kms/IT"), vault_transit_kv_engine, kv_transit_version, newkeyname, secretMap)
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
