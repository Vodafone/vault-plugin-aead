package aeadplugin

import (
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Vodafone/vault-plugin-aead/aeadutils"
	"github.com/Vodafone/vault-plugin-aead/kvutils"
	"github.com/google/tink/go/keyset"
	hclog "github.com/hashicorp/go-hclog"
	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathSyncToExternalKV(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	output, err := SyncToExternalKV(b, ctx, req, data)
	return &logical.Response{
		Data: output,
	}, err
}
func (b *backend) pathSyncFromExternalKV(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	output, err := SyncFromExternalKV(b, ctx, req, data)
	return &logical.Response{
		Data: output,
	}, err
}

func (b *backend) pathSyncKV(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	kvMap := map[string]interface{}{}
	rtnMap := make(map[string]interface{})
	var res *logical.Response

	var kvOptions kvutils.KVOptions
	err := resolveKvOptions(&kvOptions)
	if err != nil {
		hclog.L().Error("\nfailed to read vault config")
		return nil, err
	}

	if kvOptions.Vault_kv_active == "true" {

		// get the kv client
		kvClient, err := kvutils.KvGetClientWithApprole(kvOptions.Vault_kv_url, "", kvOptions.Vault_kv_approle_id, kvOptions.Vault_kv_secret_id, kvOptions.Vault_kv_writer_role, kvOptions.Vault_secretgenerator_iam_role)
		if err != nil {
			rtnMap["Error"] = "failed to connect to vault: " + err.Error()
			res.Data = rtnMap
			return res, nil
		}
		kvConnection := kvutils.KVConnection{Client: kvClient, Engine: kvOptions.Vault_kv_engine, Version: kvOptions.Vault_kv_version, Url: kvOptions.Vault_kv_url}

		kvMap, err = b.readKV(ctx, kvConnection, false)

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

	var kvOptions kvutils.KVOptions
	err := resolveKvOptions(&kvOptions)
	if err != nil {
		hclog.L().Error("\nfailed to read vault config")
		return nil, err
	}

	if kvOptions.Vault_kv_active == "true" {
		// get the kv client
		kvClient, err := kvutils.KvGetClientWithApprole(kvOptions.Vault_kv_url, "", kvOptions.Vault_kv_approle_id, kvOptions.Vault_kv_secret_id, kvOptions.Vault_kv_writer_role, kvOptions.Vault_secretgenerator_iam_role)
		if err != nil {
			m["Error"] = "failed to connect to vault: " + err.Error()
			return &logical.Response{
				Data: m,
			}, nil
		}
		kvConnection := kvutils.KVConnection{Client: kvClient, Engine: kvOptions.Vault_kv_engine, Version: kvOptions.Vault_kv_version, Url: kvOptions.Vault_kv_url}

		m, err = b.readKV(ctx, kvConnection)

		if err != nil {
			m = map[string]interface{}{}
			m["error"] = err.Error()
		}
	}
	return &logical.Response{
		Data: m,
	}, nil
}

func (b *backend) readKV(
	ctx context.Context,
	kv kvutils.KVConnection,
	mask ...bool,
) (map[string]interface{}, error) {
	client := kv.Client
	// we are looking for:
	// engine: kv_engine
	// path: gcm/addressline and siv/addressline
	// data and aad

	// read the paths
	paths, err := kvutils.KvGetSecretPaths(client, kv.Engine, kv.Version, kv.Path)

	if err != nil || paths == nil {
		hclog.L().Error("failed to read paths")
	}
	consulKV := make(map[string]interface{})

	// iterate through the paths
	for _, path := range paths {
		keyFound := false
		kvsecret, err := kvutils.KvGetSecret(client, kv.Engine, kv.Version, path)
		if err != nil {
			errMsg := fmt.Sprintf("failed to read the secrets in folder %s: %s", path, err)
			hclog.L().Error(errMsg)
			return nil, fmt.Errorf(errMsg)
		}

		if kvsecret == nil {
			errMsg := fmt.Sprintf("failed to read the secrets in folder %s: secret not found", path)
			hclog.L().Error(errMsg)
			return nil, fmt.Errorf(errMsg)
		}

		if kvsecret.Data == nil {
			errMsg := fmt.Sprintf("failed to read the secrets in folder %s: data not found", path)
			hclog.L().Error(errMsg)
			return nil, fmt.Errorf(errMsg)
		}

		if strings.HasPrefix(path, "gcm/") || strings.HasPrefix(path, "siv/") {
			keyFound = true
			jsonKey, ok := kvsecret.Data["data"]
			if !ok {
				hclog.L().Error("failed to read back the aead key " + path)
			}

			if extractedKeySet, _, err := isSecretAnAEADKeyset(jsonKey, path); err != nil {
				hclog.L().Error("failed to read vailid secret key " + path)
			} else {
				// hclog.L().Info("valid secret key")
				if mask == nil || mask[0] == true {
					consulKV[path] = aeadutils.MuteKeyMaterial(extractedKeySet)
				} else {
					consulKV[path] = extractedKeySet
				}
			}

			jsonAad, ok := kvsecret.Data["aad"]
			if !ok {
				hclog.L().Error("failed to read back the aad key " + path)
			}
			if extractedAD, err := extractADFromSecret(jsonAad, path); err != nil {
				hclog.L().Error("failed to read valid secret key " + path)
			} else {
				consulKV["ADDITIONAL_DATA-"+path] = extractedAD
			}
		} else if strings.HasSuffix(path, "GCM") || strings.HasSuffix(path, "SIV") {
			keyFound = true
			// process the path
			pathParts := strings.Split(path, "/")
			secretName := pathParts[len(pathParts)-1]
			secretParts := strings.Split(secretName, "_")
			// TODO: split into different func
			secretMetadata := map[string]string{}

			// secretMetadata["namespace"] = secretParts[0]
			// secretMetadata["encryption-type"] = secretParts[1]
			secretMetadata["key-name"] = strings.ToLower(secretParts[2])
			// secretMetadata["alg"] = secretParts[3]
			secretMetadata["type"] = strings.ToLower(secretParts[4])

			newPath := secretMetadata["type"] + "/" + secretMetadata["key-name"]

			var vaultWrapper kvutils.VaultClientWrapper = kvutils.VaultClientWrapperImpl{Client: client}
			wrappedkey := fmt.Sprintf("%v", kvsecret.Data["key"])
			base64Keyset, err := kvutils.UnwrapKeyset(&vaultWrapper, kvutils.EncryptedKVKey{Ciphertext: wrappedkey}, kv.Kek, kv.Transit_engine)
			if err != nil {
				hclog.L().Error("failed to unwrap key")
			}
			// TODO: Use the output key instead of _
			_, err = aeadutils.ValidateB64Key(base64Keyset)
			if err != nil {
				hclog.L().Error("Wrapped key is invalid")
			}
			// Decode the B64 key to bytes
			keysetByte, err := b64.StdEncoding.DecodeString(base64Keyset)
			if err != nil {
				hclog.L().Error("failed to read back the aead key " + secretMetadata["key-name"])
			}
			// validate the json bytes
			valid := json.Valid(keysetByte)
			if !valid {
				hclog.L().Error("the JSON is not valid for the key " + secretMetadata["key-name"])
			}
			// Get the json string of the key
			var keysetString string = string(keysetByte)
			// TODO: Find the duplicate code
			// extract the json data into a Map
			var key map[string]interface{}
			err = json.Unmarshal([]byte(keysetString), &key)
			if err != nil {
				hclog.L().Error("failed to extract the keysetstring for the key " + secretMetadata["key-name"])
			}

			// struct the vault secret instace
			secret := map[string]interface{}{}
			secret[secretMetadata["key-name"]] = key
			secretBytes, _ := json.Marshal(secret)
			secretString := string(secretBytes)
			if extractedKeySet, _, err := isSecretAnAEADKeyset(secretString, newPath); err != nil {
				hclog.L().Error("failed to read valid secret key " + newPath)
			} else {
				// hclog.L().Info("valid secret key")
				if mask == nil || mask[0] == true {
					consulKV[secretName] = aeadutils.MuteKeyMaterial(extractedKeySet)
				} else {
					consulKV[secretName] = extractedKeySet
				}
			}

			// var jsonAad map[string]interface{}
			// jsonAad[path] = path
			// consulKV["ADDITIONAL_DATA-"+newPath] = newPath
		}

		if !keyFound {
			hclog.L().Info("failed to read back any gcm or siv AEAD keys in KV secret " + path)
		}

	}

	return consulKV, nil
}
func resolveKvOptions(kvOptions *kvutils.KVOptions) error {

	kvOptions.Vault_kv_active = "false" // default
	kv_active, ok := AEAD_CONFIG.Get("VAULT_KV_ACTIVE")
	if ok {
		kvOptions.Vault_kv_active = fmt.Sprintf("%v", kv_active)
	}

	Vault_url, ok := AEAD_CONFIG.Get("VAULT_KV_URL")
	if ok {
		kvOptions.Vault_kv_url = fmt.Sprintf("%v", Vault_url)
	}

	Vault_approleid, ok := AEAD_CONFIG.Get("VAULT_KV_APPROLE_ID")
	if ok {
		kvOptions.Vault_kv_approle_id = fmt.Sprintf("%v", Vault_approleid)
	}

	Vault_secretid, ok := AEAD_CONFIG.Get("VAULT_KV_SECRET_ID")
	if ok {
		kvOptions.Vault_kv_secret_id = fmt.Sprintf("%v", Vault_secretid)
	}

	kv_engine, ok := AEAD_CONFIG.Get("VAULT_KV_ENGINE")
	if ok {
		kvOptions.Vault_kv_engine = fmt.Sprintf("%v", kv_engine)
	} else {
		kvOptions.Vault_kv_engine = "secret" // default
	}

	kv_version, ok := AEAD_CONFIG.Get("VAULT_KV_VERSION")
	if ok {
		kvOptions.Vault_kv_version = fmt.Sprintf("%v", kv_version)
	} else {
		kvOptions.Vault_kv_version = "v2" // default

	}

	kvOptions.Vault_transit_active = "false" // default
	Vault_transit_active, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_ACTIVE")
	if ok {
		kvOptions.Vault_transit_active = fmt.Sprintf("%v", Vault_transit_active)
	}
	Vault_transit_url, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_URL")
	if ok {
		kvOptions.Vault_transit_url = fmt.Sprintf("%v", Vault_transit_url)
	}
	Vault_transit_approle_id, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_APPROLE_ID")
	if ok {
		kvOptions.Vault_transit_approle_id = fmt.Sprintf("%v", Vault_transit_approle_id)
	}
	Vault_transit_secret_id, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_SECRET_ID")
	if ok {
		kvOptions.Vault_transit_secret_id = fmt.Sprintf("%v", Vault_transit_secret_id)
	}
	Vault_transit_kv_engine, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_KV_ENGINE")
	if ok {
		kvOptions.Vault_transit_kv_engine = fmt.Sprintf("%v", Vault_transit_kv_engine)
	}
	Vault_transit_kv_pull_path, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_KV_PULL_PATH")
	if ok {
		kvOptions.Vault_transit_kv_pull_path = fmt.Sprintf("%v", Vault_transit_kv_pull_path)
	}
	Vault_transit_kv_push_path, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_KV_PUSH_PATH")
	if ok {
		kvOptions.Vault_transit_kv_push_path = fmt.Sprintf("%v", Vault_transit_kv_push_path)
	}
	Vault_transit_engine, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_ENGINE")
	if ok {
		kvOptions.Vault_transit_engine = fmt.Sprintf("%v", Vault_transit_engine)
	}
	Vault_transit_kv_version, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_KV_VERSION")
	if ok {
		kvOptions.Vault_transit_kv_version = fmt.Sprintf("%v", Vault_transit_kv_version)
	}
	Vault_transit_namespace, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_NAMESPACE")
	if ok {
		kvOptions.Vault_transit_namespace = fmt.Sprintf("%v", Vault_transit_namespace)
	}
	Vault_transit_kek, ok := AEAD_CONFIG.Get("VAULT_TRANSIT_KEK")
	if ok {
		kvOptions.Vault_transit_kek = fmt.Sprintf("%v", Vault_transit_kek)
	}

	Vault_kv_writer_role, ok := AEAD_CONFIG.Get("VAULT_KV_WRITER_ROLE")
	if ok {
		kvOptions.Vault_kv_writer_role = fmt.Sprintf("%v", Vault_kv_writer_role)
	}

	Vault_secretgenerator_iam_role, ok := AEAD_CONFIG.Get("VAULT_KV_SECRETGENERATOR_IAM_ROLE")
	if ok {
		kvOptions.Vault_secretgenerator_iam_role = fmt.Sprintf("%v", Vault_secretgenerator_iam_role)
	}

	return nil
}
func saveToKV(keyNameIn string, keyJsonIn interface{}, env ...KVEnvitonment) (bool, error) {

	var err error
	var kvOptions kvutils.KVOptions
	if env == nil || env[0].Options == (kvutils.KVOptions{}) {
		err := resolveKvOptions(&kvOptions)
		if err != nil {
			hclog.L().Error("\nfailed to read vault config")
			return false, err
		}
	} else {
		kvOptions = env[0].Options
	}

	if kvOptions.Vault_kv_active == "false" {
		return true, nil
	}

	potentialAEADKey := fmt.Sprintf("%v", keyJsonIn)
	if potentialAEADKey == "" {
		return true, nil
	}

	// kh, err := aeadutils.ValidateKeySetJson(potentialAEADKey)
	_, err = aeadutils.ValidateKeySetJson(potentialAEADKey)

	if err != nil {
		return true, nil
	}

	// ksi := kh.KeysetInfo()
	// ki := ksi.KeyInfo[len(ksi.KeyInfo)-1]
	// keyTypeURL := ki.GetTypeUrl()

	// hclog.L().Info("saveToKV:" + keyNameIn + " Type: " + keyTypeURL)

	// get a client
	// get a client
	var client *vault.Client
	if env == nil || env[0].Connection == (kvutils.KVConnection{}) {
		client, err = kvutils.KvGetClientWithApprole(kvOptions.Vault_kv_url, "", kvOptions.Vault_kv_approle_id, kvOptions.Vault_kv_secret_id, kvOptions.Vault_kv_writer_role, kvOptions.Vault_secretgenerator_iam_role)
		if err != nil {
			hclog.L().Error("\nfailed to initialize Vault client2")
			return false, err
		}
	} else {
		client = env[0].Connection.Client
	}

	// // create a secret
	keyJsonInStr := fmt.Sprintf("%s", keyJsonIn)
	var keySetStruct aeadutils.KeySetStruct
	err = json.Unmarshal([]byte(keyJsonInStr), &keySetStruct)
	if err != nil {
		hclog.L().Error("\nfailed to unmarshall the keyset into a struct")
	}

	keyMap := make(map[string]interface{})
	// keyMap[aeadutils.RemoveKeyPrefix(keyNameIn)] = keyJsonIn
	keyMap[aeadutils.RemoveKeyPrefix(keyNameIn)] = keySetStruct

	// Marshal the map into a JSON string.
	keyData, err := json.Marshal(keyMap)
	if err != nil {
		hclog.L().Error(err.Error())
	}
	jsonKeyStr := string(keyData)

	aadMap := make(map[string]interface{})
	aadMap[aeadutils.RemoveKeyPrefix(keyNameIn)] = aeadutils.RemoveKeyPrefix(keyNameIn)
	// Marshal the map into a JSON string.
	aadData, err := json.Marshal(aadMap)
	if err != nil {
		hclog.L().Error(err.Error())
	}

	jsonAadStr := string(aadData)

	// secretMap["aad"] = aadMap
	secretMap := make(map[string]interface{})

	secretMap["data"] = jsonKeyStr
	secretMap["aad"] = jsonAadStr

	secret, err := putAndCheckKvSecret(client, kvOptions.Vault_kv_engine, kvOptions.Vault_kv_version, keyNameIn, secretMap)
	if err != nil {
		return false, err
	}

	if _, _, err = isSecretAnAEADKeyset(secret, aeadutils.RemoveKeyPrefix(keyNameIn)); err != nil {
		return false, err
	}
	if env != nil {
		env[0].Connection = (kvutils.KVConnection{})
	}
	_, err = saveToExternalKV(keyNameIn, fmt.Sprintf("%s", keyJsonIn), env...)
	if err != nil {
		return false, err
	}

	// shouldn't get here
	return true, nil
}

func putAndCheckKvSecret(client *vault.Client, Vault_kv_engine string, Vault_kv_version string, keyNameIn string, secretMap map[string]interface{}) (interface{}, error) {

	_, err := kvutils.KvPutSecret(client, Vault_kv_engine, Vault_kv_version, keyNameIn, secretMap)
	if err != nil {
		hclog.L().Error("failed to put a secret to KV")
		return nil, err
	}

	kvsecret, err := kvutils.KvGetSecret(client, Vault_kv_engine, Vault_kv_version, keyNameIn)
	if err != nil {
		errMsg := fmt.Sprintf("failed to read the secrets in folder %s: %s", keyNameIn, err)
		hclog.L().Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	if kvsecret == nil {
		errMsg := fmt.Sprintf("failed to read the secrets in folder %s: secret not found", keyNameIn)
		hclog.L().Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	if kvsecret.Data == nil {
		errMsg := fmt.Sprintf("failed to read the secrets in folder %s: data not found", keyNameIn)
		hclog.L().Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	secret, ok := kvsecret.Data["data"]
	if !ok {
		hclog.L().Error("failed to extract the data from the secrets in folder:" + keyNameIn)
		return nil, err
	}
	return secret, nil
}

type KVEnvitonment struct {
	Options    kvutils.KVOptions
	Connection kvutils.KVConnection
	Synclist   map[string]interface{}
}

func saveToExternalKV(keyNameIn string, keyjson string, env ...KVEnvitonment) (bool, error) {
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

	var err error
	var kvOptions kvutils.KVOptions
	if env == nil || env[0].Options == (kvutils.KVOptions{}) {
		err := resolveKvOptions(&kvOptions)
		if err != nil {
			hclog.L().Error("\nfailed to read vault config")
			return false, err
		}
	} else {
		kvOptions = env[0].Options
	}

	if kvOptions.Vault_transit_active == "false" {
		return true, nil
	}

	var syncMap map[string]interface{}
	if env == nil || env[0].Synclist == nil {
		syncMap, err = readKeysTobeSynced(kvOptions)
		if err != nil {
			// not an error just means we won't sync to the transit kv
			hclog.L().Info("\nfailed to read keys to be synced" + err.Error())
			return true, nil
		}
	} else {
		syncMap = env[0].Synclist
	}

	// do we have the same key in the list to be synced
	toSyncIntf, ok := syncMap[keyNameIn]
	if !ok {
		// not an error just means we won't sync to the transit kv
		hclog.L().Info("don't sync this key " + keyNameIn)
		return true, nil
	}
	toSync := fmt.Sprintf("%v", toSyncIntf)
	if toSync != "true" {
		hclog.L().Info("don't sync this key " + keyNameIn)
		return true, nil
	}

	// OK, we want to sync this key

	// get a client
	var client *vault.Client
	if env == nil || env[0].Connection == (kvutils.KVConnection{}) {
		client, err = kvutils.KvGetClientWithApprole(kvOptions.Vault_transit_url, kvOptions.Vault_transit_namespace, kvOptions.Vault_transit_approle_id, kvOptions.Vault_transit_secret_id, kvOptions.Vault_kv_writer_role, kvOptions.Vault_secretgenerator_iam_role)
		if err != nil {
			hclog.L().Error("\nfailed to initialize Vault client3")
			return false, err
		}
	} else {
		client = env[0].Connection.Client
	}

	// make a new keyname
	keyname := aeadutils.RemoveKeyPrefix(keyNameIn)
	newkeyname, err := kvutils.DeriveKeyName(kvOptions.Vault_transit_namespace, keyname, keyjson)
	if err != nil {
		return false, err
	}
	hclog.L().Info("newkeyname: " + newkeyname)

	//wrap the key
	var vaultWrapper kvutils.VaultClientWrapper = kvutils.VaultClientWrapperImpl{Client: client.WithNamespace(kvOptions.Vault_transit_namespace)}
	wrappedkey, err := kvutils.WrapKeyset(&vaultWrapper, keyjson, kvOptions.Vault_transit_kek, kvOptions.Vault_transit_engine)
	if err != nil {
		hclog.L().Error("failed to wrap key")
	}

	base64Keyset, err := kvutils.UnwrapKeyset(&vaultWrapper, kvutils.EncryptedKVKey{Ciphertext: wrappedkey}, kvOptions.Vault_transit_kek, kvOptions.Vault_transit_engine)
	if err != nil {
		hclog.L().Error("failed to unwrap key")
	}
	_, err = aeadutils.ValidateB64Key(base64Keyset)
	if err != nil {
		hclog.L().Error("Wrapped key is invalid")
	}

	secretMap := map[string]interface{}{}
	secretMap["key"] = wrappedkey
	_, err = kvutils.KvPutSecret(client.WithNamespace(kvOptions.Vault_transit_namespace), kvOptions.Vault_transit_kv_engine, kvOptions.Vault_transit_kv_version, kvOptions.Vault_transit_kv_push_path+"/"+newkeyname, secretMap)
	if err != nil {
		hclog.L().Error("failed to write to transit")
	}
	return true, nil
}

func isSecretAnAEADKeyset(secret interface{}, fName string) (string, *keyset.Handle, error) {
	secretStr := fmt.Sprintf("%v", secret)
	fieldName := aeadutils.RemoveKeyPrefix(fName)
	var jMap map[string]aeadutils.KeySetStruct
	if err := json.Unmarshal([]byte(secretStr), &jMap); err != nil {
		hclog.L().Error("failed to unmarshall the secret " + fName)
		return "", nil, err
	}

	keysetAsMap := jMap[fieldName]
	keysetAsByteArray, err := json.Marshal(keysetAsMap)
	if err != nil {
		hclog.L().Error("failed to marshall " + fName)
	}
	jsonToValidate := string(keysetAsByteArray)
	kh, err := aeadutils.ValidateKeySetJson(jsonToValidate)
	if err != nil {
		hclog.L().Error("failed to recreate a key handle from the json " + fName)
		return "", nil, err
	}
	return jsonToValidate, kh, nil
}

func extractADFromSecret(secret interface{}, fName string) (string, error) {
	secretStr := fmt.Sprintf("%v", secret)
	fieldName := aeadutils.RemoveKeyPrefix(fName)
	var jMap map[string]interface{}
	if err := json.Unmarshal([]byte(secretStr), &jMap); err != nil {
		hclog.L().Error("failed to unmarshall the secret " + fName)
		return "", err
	}
	adStr := fmt.Sprintf("%v", jMap[fieldName])

	return adStr, nil
}

func deleteFromKV(k string) (bool, error) {
	hclog.L().Info("deleteFromKV: NOT IMPLEMENTED: " + k)
	return true, nil
}

func storeKeysTobeSynced(kvOptions kvutils.KVOptions, keyMap map[string]interface{}) error {
	// get a client
	client, err := kvutils.KvGetClientWithApprole(kvOptions.Vault_kv_url, "", kvOptions.Vault_kv_approle_id, kvOptions.Vault_kv_secret_id, kvOptions.Vault_kv_writer_role, kvOptions.Vault_secretgenerator_iam_role)
	if err != nil {
		hclog.L().Error("Failed to initialise kv:" + err.Error())
		return err
	}

	// read the synclist secret
	kvsecret, err := kvutils.KvGetSecret(client, kvOptions.Vault_kv_engine, kvOptions.Vault_kv_version, "synclist")
	if err != nil || kvsecret.Data == nil {
		// its OK for this to be missing
		hclog.L().Info("Failed to read the synclist secret:" + err.Error())
	}

	// do we have a secret with data, if not write a new one
	if kvsecret == nil || kvsecret.Data == nil {
		_, err = kvutils.KvPutSecret(client, kvOptions.Vault_kv_engine, kvOptions.Vault_kv_version, "synclist", keyMap)
		if err != nil {
			hclog.L().Error("failed to put a secret to KV:" + err.Error())
			return err
		} else {
			hclog.L().Info("successfully to put a secret to KV")
			return nil
		}
	}

	// add the new elements
	for k, v := range keyMap {
		kvsecret.Data[k] = v
	}

	// write the updated
	_, err = kvutils.KvPutSecret(client, kvOptions.Vault_kv_engine, kvOptions.Vault_kv_version, "synclist", kvsecret.Data)
	if err != nil {
		hclog.L().Error("failed to put a secret to KV:" + err.Error())
		return err
	}
	return nil
}

func readKeysTobeSynced(kvOptions kvutils.KVOptions) (map[string]interface{}, error) {
	// get a client
	client, err := kvutils.KvGetClientWithApprole(kvOptions.Vault_kv_url, "", kvOptions.Vault_kv_approle_id, kvOptions.Vault_kv_secret_id, kvOptions.Vault_kv_writer_role, kvOptions.Vault_secretgenerator_iam_role)
	if err != nil {
		hclog.L().Error("Failed to initialise kv:" + err.Error())
		return nil, err
	}

	// read the synclist secret
	kvsecret, err := kvutils.KvGetSecret(client, kvOptions.Vault_kv_engine, kvOptions.Vault_kv_version, "synclist")
	if err != nil {
		errMsg := fmt.Sprintf("failed to read the secrets in folder %s: %s", "synclist", err)
		hclog.L().Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	if kvsecret == nil {
		errMsg := fmt.Sprintf("failed to read the secrets in folder %s: secret not found", "synclist")
		hclog.L().Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	if kvsecret.Data == nil {
		errMsg := fmt.Sprintf("failed to read the secrets in folder %s: data not found", "synclist")
		hclog.L().Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	// return the map of keys to be synced
	return kvsecret.Data, nil
}

func SyncToExternalKV(b *backend, ctx context.Context, req *logical.Request, data *framework.FieldData) (map[string]interface{}, error) {
	rtnMap := make(map[string]interface{})

	var kvOptions kvutils.KVOptions
	err := resolveKvOptions(&kvOptions)
	if err != nil {
		hclog.L().Error("\nfailed to read vault config: " + err.Error())
		rtnMap["Error"] = "failed to read vault config: " + err.Error()
		return rtnMap, err
	}

	if kvOptions.Vault_kv_active != "true" {
		err = errors.New("the config value VAULT_KV_ACTIVE must set to true")
		rtnMap["Error"] = err.Error()
		return rtnMap, err
	}

	err = storeKeysTobeSynced(kvOptions, data.Raw)
	if err != nil {
		rtnMap["Error"] = "failed to store synclist: " + err.Error()
		return rtnMap, err
	}

	// get the kv client
	kvClient, err := kvutils.KvGetClientWithApprole(kvOptions.Vault_kv_url, "", kvOptions.Vault_kv_approle_id, kvOptions.Vault_kv_secret_id, kvOptions.Vault_kv_writer_role, kvOptions.Vault_secretgenerator_iam_role)
	if err != nil {
		rtnMap["Error"] = "failed to connect to vault: " + err.Error()
		return rtnMap, err
	}
	kvConnection := kvutils.KVConnection{Client: kvClient, Engine: kvOptions.Vault_kv_engine, Version: kvOptions.Vault_kv_version, Url: kvOptions.Vault_kv_url}

	// get all the keys in KV
	kvMap, err := b.readKV(ctx, kvConnection, false)
	if err != nil || kvMap == nil {
		rtnMap["Error"] = err.Error()
		return rtnMap, err
	}

	var syncMap map[string]interface{}
	syncMap, err = readKeysTobeSynced(kvOptions)
	if err != nil {
		// not an error just means we won't sync to the transit kv
		hclog.L().Info("\nfailed to read keys to be synced" + err.Error())
		rtnMap["Error"] = "failed to read keys to be synced : " + err.Error()
		return rtnMap, err
	}
	var env KVEnvitonment
	env.Options = kvOptions
	env.Synclist = syncMap
	for keyName, v := range syncMap {
		if fmt.Sprintf("%s", v) != "true" {
			rtnMap[keyName] = "Skipping key" + keyName
			continue
		}
		jsonIntf, ok := kvMap[keyName]
		if !ok {
			rtnMap[keyName] = "Error: key not found in KV: " + keyName
			continue
		}
		// ok we have the key in KV, lets extract the json as a string and send it to transitkv
		keyJson := fmt.Sprint(jsonIntf)

		_, err := saveToExternalKV(keyName, keyJson, env)
		if err != nil {
			rtnMap[keyName] = "Error saving to transit: " + err.Error()
		} else {
			rtnMap[keyName] = "OK"
		}
	}
	return rtnMap, nil
}

func SyncFromExternalKV(b *backend, ctx context.Context, req *logical.Request, data *framework.FieldData) (map[string]interface{}, error) {

	rtnMap := make(map[string]interface{})

	var kvOptions kvutils.KVOptions
	err := resolveKvOptions(&kvOptions)
	if err != nil {
		hclog.L().Error("\nfailed to read vault config: " + err.Error())
		rtnMap["Error"] = "failed to read vault config: " + err.Error()
		return rtnMap, err
	}

	if kvOptions.Vault_kv_active != "true" {
		err = errors.New("the config value VAULT_KV_ACTIVE must set to true")
		rtnMap["Error"] = err.Error()
		return rtnMap, err
	}
	if kvOptions.Vault_transit_active != "true" {
		err = errors.New("the config value VAULT_TRANSIT_ACTIVE must set to true")
		rtnMap["Error"] = err.Error()
		return rtnMap, err
	}

	err = storeKeysTobeSynced(kvOptions, data.Raw)
	if err != nil {
		rtnMap["Error"] = "failed to store synclist: " + err.Error()
		return rtnMap, err
	}

	// get the kv client
	externalKvClient, err := kvutils.KvGetClientWithApprole(kvOptions.Vault_transit_url, kvOptions.Vault_transit_namespace, kvOptions.Vault_transit_approle_id, kvOptions.Vault_transit_secret_id, kvOptions.Vault_kv_writer_role, kvOptions.Vault_secretgenerator_iam_role)
	if err != nil {
		rtnMap["Error"] = "failed to connect to external vault: " + err.Error()
		return rtnMap, err
	}
	externalKVConnection := kvutils.KVConnection{
		Client: externalKvClient.WithNamespace(kvOptions.Vault_transit_namespace),
		Engine: kvOptions.Vault_transit_kv_engine, Version: kvOptions.Vault_transit_kv_version,
		Url:            kvOptions.Vault_transit_url,
		Namespace:      kvOptions.Vault_transit_namespace,
		Path:           kvOptions.Vault_transit_kv_pull_path + "/",
		Kek:            kvOptions.Vault_transit_kek,
		Transit_engine: kvOptions.Vault_transit_engine,
	}

	// get all the keys in KV
	kvMap, err := b.readKV(ctx, externalKVConnection, false)
	if err != nil || kvMap == nil {
		rtnMap["Error"] = err.Error()
		return rtnMap, err
	}
	var syncMap map[string]interface{}
	syncMap, err = readKeysTobeSynced(kvOptions)
	if err != nil {
		// not an error just means we won't sync to the transit kv
		hclog.L().Info("\nfailed to read keys to be synced" + err.Error())
		rtnMap["Error"] = "failed to read keys to be synced : " + err.Error()
		return rtnMap, err
	}
	var env KVEnvitonment
	env.Options = kvOptions
	env.Synclist = syncMap

	for keyName, v := range syncMap {
		if fmt.Sprintf("%s", v) != "true" {
			rtnMap[keyName] = "Skipping key" + keyName
			continue
		}
		jsonIntf, ok := kvMap[keyName]
		if !ok {
			rtnMap[keyName] = "Error: key not found in KV: " + keyName
			continue
		}
		// ok we have the key in KV, lets extract the json as a string and send it to transitkv
		keyJson := fmt.Sprint(jsonIntf)
		//derive keyname
		newKeyName, err := kvutils.DeriveKVKeyName("", keyName, keyJson)
		if err != nil {
			rtnMap[keyName] = "failed to derive keyname: " + err.Error()
			continue
		}
		_, err = saveToKV(newKeyName, keyJson, env)
		if err != nil {
			rtnMap[keyName] = "Error saving to transit: " + err.Error()
			continue
		}
		rtnMap[keyName] = "OK"

	}
	return rtnMap, nil
}
