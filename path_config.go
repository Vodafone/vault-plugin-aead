package aeadplugin

import (
	"bytes"
	"context"
	b64 "encoding/base64"
	"fmt"
	"strings"

	"github.com/Vodafone/vault-plugin-aead/aeadutils"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	cmap "github.com/orcaman/concurrent-map"
)

var AEAD_CONFIG = cmap.New()

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.configWriteOverwriteCheck(ctx, req, data, false, true)
}
func (b *backend) pathConfigOverwrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.configWriteOverwriteCheck(ctx, req, data, true, true)

}
func (b *backend) configWriteOverwriteCheck(ctx context.Context, req *logical.Request, data *framework.FieldData, overwriteConfig bool, overwriteKV bool) (*logical.Response, error) {

	// retrieve the config from storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	// iterate through the supplied map, adding it to the config map
	for k, v := range data.Raw {

		prefix := aeadutils.GetKeyPrefix(k, fmt.Sprintf("%v", v), nil)
		k = prefix + k

		if !overwriteConfig {
			// don't do this if we already have a key in the config - prevents overwrite
			_, ok := AEAD_CONFIG.Get(k)
			if ok {
				hclog.L().Info("configWriteOverwriteCheck - key already exists " + k)
				continue
			}
		}
		AEAD_CONFIG.Set(k, v)
		if overwriteKV {
			ok, err := saveToKV(k, v)
			if !ok || err != nil {
				hclog.L().Error("configWriteOverwriteCheck failed to save to KV:" + k + " Error:" + err.Error())
			}
		}
	}

	entry, err := logical.StorageEntryJSON("config", AEAD_CONFIG)
	// entry, err := logical.StorageEntryJSON("config", data.Raw)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// retrieve the config from storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	// iterate through the supplied map, deleting from the store
	for k := range data.Raw {
		AEAD_CONFIG.Remove(k)
		ok, err := deleteFromKV(k)
		if !ok || err != nil {
			hclog.L().Error("failed to delete from KV " + k)
		}
	}

	entry, err := logical.StorageEntryJSON("config", AEAD_CONFIG)
	// entry, err := logical.StorageEntryJSON("config", data.Raw)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// retrieve the config from storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}
	result := make(map[string]interface{}, len(AEAD_CONFIG.Items()))
	for k, v := range AEAD_CONFIG.Items() {
		_, err := aeadutils.ValidateKeySetJson(v.(string))
		if err == nil {
			// key is valid
			v = aeadutils.MuteKeyMaterial(v.(string))
		}
		result[k] = v
	}
	
	// Add total keys count
	result["total_keys"] = len(AEAD_CONFIG.Items())
	result["MountPoint"] = req.MountPoint
	
	return &logical.Response{
		Data: result,
	}, nil
}

func (b *backend) pathReadKeyTypes(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// retrieve the config from storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	m := map[string]interface{}{}
	detCount := 0
	nonDetCount := 0
	for k, v := range AEAD_CONFIG.Items() {
		str := ""
		_, determinstic := aeadutils.IsKeyJsonDeterministic(v)
		if determinstic {
			str = "DETERMINISTIC"
			detCount++
		} else {
			str = "NON DETERMINISTIC"
			nonDetCount++
		}
		m[k] = str
	}
	
	// Add summary statistics
	m["summary"] = map[string]interface{}{
		"total_keys":             len(AEAD_CONFIG.Items()),
		"deterministic_keys":     detCount,
		"non_deterministic_keys": nonDetCount,
	}
	
	return &logical.Response{
		Data: m,
	}, nil
}

func (b *backend) getAeadConfig(ctx context.Context, req *logical.Request) error {

	consulConfig, err := b.readConsulConfig(ctx, req.Storage)

	if err != nil {
		return err
	}

	// if the config retrieved from the storage is null use the in memory config
	// add config from consul into the AEAD_CONFIG cache
	for k, v := range consulConfig {
		AEAD_CONFIG.Set(k, v)
	}

	// remove config from the cache anything that is not in consul
	// only sync if consulConfig is not nil (config entry exists in storage)
	if consulConfig != nil {
		for k := range AEAD_CONFIG.Items() {
			if _, ok := consulConfig[k]; !ok {
				AEAD_CONFIG.Remove(k)
			}
		}
	}

	return nil
}

func (b *backend) readConsulConfig(ctx context.Context, s logical.Storage) (map[string]interface{}, error) {

	consulConfig := make(map[string]interface{})
	entry, err := s.Get(ctx, "config")

	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	if err := entry.DecodeJSON(&consulConfig); err != nil {
		return nil, err
	}
	return consulConfig, nil
}

func (b *backend) findAllKeysWithPrefix(requestedKeyName string) []string {
	// Find all key variants matching the requested name
	var foundKeys []string

	// Try exact match first
	if _, ok := AEAD_CONFIG.Get(requestedKeyName); ok {
		foundKeys = append(foundKeys, requestedKeyName)
	}

	// Try with gcm/ prefix
	gcmKeyName := "gcm/" + requestedKeyName
	if _, ok := AEAD_CONFIG.Get(gcmKeyName); ok {
		foundKeys = append(foundKeys, gcmKeyName)
	}

	// Try with siv/ prefix
	sivKeyName := "siv/" + requestedKeyName
	if _, ok := AEAD_CONFIG.Get(sivKeyName); ok {
		foundKeys = append(foundKeys, sivKeyName)
	}

	// Return all matching keys
	return foundKeys
}

func (b *backend) pathKeyRotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// retrieve the config from storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	rotatedCount := 0
	var rotatedKeys []string
	var notFoundKeys []string
	var failedKeys []map[string]string
	var keysToProcess []string

	// Check if specific keys were requested for rotation
	keysParam := data.Get("keys")
	if keysParam != nil && keysParam.(string) != "" {
		// Parse comma-separated list of keys and directly access them
		keysList := strings.Split(keysParam.(string), ",")
		keysToProcess = keysList
	} else {
		// No specific keys requested - process all keys
		for keyField := range AEAD_CONFIG.Items() {
			keysToProcess = append(keysToProcess, fmt.Sprintf("%v", keyField))
		}
	}

	// Process only the requested (or all) keys
	for _, requestedKeyName := range keysToProcess {
		fieldName := strings.TrimSpace(requestedKeyName)

		// Find all key variants matching this name
		actualKeyNames := b.findAllKeysWithPrefix(fieldName)
		if len(actualKeyNames) == 0 {
			// No keys found for this name
			hclog.L().Warn("Key not found in config: " + fieldName)
			notFoundKeys = append(notFoundKeys, fieldName)
			continue
		}

		// Rotate all found key variants
		for _, actualKeyName := range actualKeyNames {
			// Get the key directly from config
			encryptionKeyVal, ok := AEAD_CONFIG.Get(actualKeyName)
			if !ok {
				// Should not happen since we just found it, but check anyway
				hclog.L().Warn("Key disappeared from config: " + actualKeyName)
				failedKeys = append(failedKeys, map[string]string{
					"key":   actualKeyName,
					"error": "key disappeared from config",
				})
				continue
			}

			keyStr := fmt.Sprintf("%v", encryptionKeyVal)
			_, err := aeadutils.ValidateKeySetJson(keyStr)
			if err != nil {
				// not a valid key
				hclog.L().Warn("Invalid keyset JSON for key: " + actualKeyName)
				failedKeys = append(failedKeys, map[string]string{
					"key":   actualKeyName,
					"error": "invalid keyset JSON: " + err.Error(),
				})
				continue
			}

			encryptionKeyStr, deterministic := aeadutils.IsKeyJsonDeterministic(encryptionKeyVal)
			if deterministic {
				kh, _, err := aeadutils.CreateInsecureHandleAndDeterministicAead(encryptionKeyStr)
				if err != nil {
					hclog.L().Error("failed to create key handle for: " + actualKeyName)
					failedKeys = append(failedKeys, map[string]string{
						"key":   actualKeyName,
						"error": "failed to create key handle: " + err.Error(),
					})
					continue
				}
				aeadutils.RotateKeys(kh, true)
				b.saveKeyToConfig(kh, actualKeyName, ctx, req, true)
				rotatedCount++
				rotatedKeys = append(rotatedKeys, actualKeyName)
			} else {
				kh, _, err := aeadutils.CreateInsecureHandleAndAead(encryptionKeyStr)
				if err != nil {
					hclog.L().Error("failed to create key handle for: " + actualKeyName)
					failedKeys = append(failedKeys, map[string]string{
						"key":   actualKeyName,
						"error": "failed to create key handle: " + err.Error(),
					})
					continue
				}
				aeadutils.RotateKeys(kh, false)
				b.saveKeyToConfig(kh, actualKeyName, ctx, req, true)
				rotatedCount++
				rotatedKeys = append(rotatedKeys, actualKeyName)
			}
		}
	}

	response := map[string]interface{}{
		"rotated_keys": rotatedCount,
		"failed_keys":  len(failedKeys),
	}

	if len(rotatedKeys) > 0 {
		response["rotated_list"] = rotatedKeys
	}

	if len(failedKeys) > 0 {
		response["failed_list"] = failedKeys
	}

	if len(notFoundKeys) > 0 {
		response["not_found_keys"] = len(notFoundKeys)
		response["not_found_list"] = notFoundKeys
	}

	return &logical.Response{
		Data: response,
	}, nil
}

func (b *backend) pathUpdateKeyStatus(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// data.Raw is map[string]map[string]string
	// map['field0':map['key':'status']]
	// retrieve the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	resp := make(map[string]interface{})

	for fieldName, v := range data.Raw {
		// GET THE KEY
		encryptionkey, ok := aeadutils.GetEncryptionKey(fieldName, AEAD_CONFIG)
		if !ok {
			hclog.L().Error("failed to get an existing key")
		}
		rawKeyset := fmt.Sprintf("%s", encryptionkey)
		r := keyset.NewJSONReader(bytes.NewBufferString(rawKeyset))
		kh, err := insecurecleartextkeyset.Read(r)
		if err != nil {
			hclog.L().Error("failed to get an existing key handle")
		}

		//assert
		vMap := v.(map[string]interface{})
		for keyId, status := range vMap {
			statusStr := fmt.Sprintf("%s", status)

			// update the status, get a new key handle
			newKh, err := aeadutils.UpdateKeyStatus(kh, keyId, statusStr)
			if err != nil || newKh == nil {
				hclog.L().Error("failed to update the status")
				resp[fieldName] = "failed to update the status"
			} else {

				// save the keyhandle for the field
				b.saveKeyToConfig(newKh, fieldName, ctx, req, true)

				// extract the JSON from the new key
				buf := new(bytes.Buffer)
				jsonWriter := keyset.NewJSONWriter(buf)
				insecurecleartextkeyset.Write(newKh, jsonWriter)
				// unmarshall the keyset
				str := buf.String()
				resp[fieldName] = str
			}
		}
	}

	mutedResult := make(map[string]interface{}, len(resp))
	for k, v := range resp {
		_, err := aeadutils.ValidateKeySetJson(v.(string))
		if err == nil {
			// we do have a valid key
			v = aeadutils.MuteKeyMaterial(v.(string))
		}
		mutedResult[k] = v
	}

	return &logical.Response{
		Data: mutedResult,
	}, nil
}
func (b *backend) pathUpdateKeyMaterial(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// data.Raw is map[string]map[string]string
	// map['field0':map['key':'material']]
	// retrieve the config from storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}
	resp := make(map[string]interface{})

	for fieldName, v := range data.Raw {
		// GET THE KEY
		encryptionkey, ok := aeadutils.GetEncryptionKey(fieldName, AEAD_CONFIG)

		if !ok {
			hclog.L().Error("failed to get an existing key")
		}
		rawKeyset := fmt.Sprintf("%s", encryptionkey)
		r := keyset.NewJSONReader(bytes.NewBufferString(rawKeyset))
		kh, err := insecurecleartextkeyset.Read(r)
		if err != nil {
			hclog.L().Error("failed to get an existing key handle")
		}

		//assert
		vMap := v.(map[string]interface{})
		for keyId, material := range vMap {
			materialStr := fmt.Sprintf("%s", material)

			// update the status, get a new key handle
			newKh, err := aeadutils.UpdateKeyMaterial(kh, keyId, materialStr)
			if err != nil {
				hclog.L().Error("failed to update the material")
				resp[fieldName] = "failed to update the material"
			} else {

				// save the keyhandle for the field
				b.saveKeyToConfig(newKh, fieldName, ctx, req, true)

				// extract the JSON from the new key
				buf := new(bytes.Buffer)
				jsonWriter := keyset.NewJSONWriter(buf)
				insecurecleartextkeyset.Write(newKh, jsonWriter)
				// unmarshall the keyset
				str := buf.String()
				resp[fieldName] = str
			}
		}
	}

	mutedResult := make(map[string]interface{}, len(resp))
	for k, v := range resp {
		_, err := aeadutils.ValidateKeySetJson(v.(string))
		if err == nil {
			// valid key
			v = aeadutils.MuteKeyMaterial(v.(string))
		}
		mutedResult[k] = v
	}

	return &logical.Response{
		Data: mutedResult,
	}, nil
}
func (b *backend) pathUpdatePrimaryKeyID(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// data.Raw is map[string]string
	// map['field0':'primaryKey']]
	// retrieve the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}
	resp := make(map[string]interface{})

	for fieldName, v := range data.Raw {
		// GET THE KEY
		encryptionkey, ok := aeadutils.GetEncryptionKey(fieldName, AEAD_CONFIG)

		if !ok {
			hclog.L().Error("failed to get an existing key")
		}
		rawKeyset := fmt.Sprintf("%s", encryptionkey)
		r := keyset.NewJSONReader(bytes.NewBufferString(rawKeyset))
		kh, err := insecurecleartextkeyset.Read(r)
		if err != nil {
			hclog.L().Error("failed to get an existing key handle")
		}

		//assert
		newPrimaryKeyStr := fmt.Sprintf("%s", v)

		// update the status, get a new key handle
		newKh, err := aeadutils.UpdatePrimaryKeyID(kh, newPrimaryKeyStr)
		if err != nil {
			hclog.L().Error("failed to update the keyID")
			resp[fieldName] = "failed to update the keyID"
		} else {

			// save the keyhandle for the field
			b.saveKeyToConfig(newKh, fieldName, ctx, req, true)

			// extract the JSON from the new key
			buf := new(bytes.Buffer)
			jsonWriter := keyset.NewJSONWriter(buf)
			insecurecleartextkeyset.Write(newKh, jsonWriter)
			// unmarshall the keyset
			str := buf.String()
			resp[fieldName] = str
		}

	}

	mutedResult := make(map[string]interface{}, len(resp))
	for k, v := range resp {
		_, err := aeadutils.ValidateKeySetJson(v.(string))
		if err == nil {
			// valid key
			v = aeadutils.MuteKeyMaterial(v.(string))
		}
		mutedResult[k] = v
	}

	return &logical.Response{
		Data: mutedResult,
	}, nil
}
func (b *backend) pathUpdateKeyID(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// data.Raw is map[string]map[string]string
	// map['field0':map['key':'newkey']]
	// retrieve the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}
	resp := make(map[string]interface{})

	for fieldName, v := range data.Raw {
		// GET THE KEY
		encryptionkey, ok := aeadutils.GetEncryptionKey(fieldName, AEAD_CONFIG)

		if !ok {
			hclog.L().Error("failed to get an existing key")
		}
		rawKeyset := fmt.Sprintf("%s", encryptionkey)
		r := keyset.NewJSONReader(bytes.NewBufferString(rawKeyset))
		kh, err := insecurecleartextkeyset.Read(r)
		if err != nil {
			hclog.L().Error("failed to get an existing key handle")
		}

		//assert
		vMap := v.(map[string]interface{})
		for keyId, newKey := range vMap {
			newKeyStr := fmt.Sprintf("%s", newKey)

			// update the status, get a new key handle
			newKh, err := aeadutils.UpdateKeyID(kh, keyId, newKeyStr)
			if err != nil {
				hclog.L().Error("failed to update the keyid")
				resp[fieldName] = "failed to update the keyid"
			} else {

				// save the keyhandle for the field
				b.saveKeyToConfig(newKh, fieldName, ctx, req, true)

				// extract the JSON from the new key
				buf := new(bytes.Buffer)
				jsonWriter := keyset.NewJSONWriter(buf)
				insecurecleartextkeyset.Write(newKh, jsonWriter)
				// unmarshall the keyset
				str := buf.String()
				resp[fieldName] = str
			}
		}
	}

	mutedResult := make(map[string]interface{}, len(resp))
	for k, v := range resp {
		_, err := aeadutils.ValidateKeySetJson(v.(string))
		if err == nil {
			// valid key
			v = aeadutils.MuteKeyMaterial(v.(string))
		}
		mutedResult[k] = v
	}

	return &logical.Response{
		Data: mutedResult,
	}, nil
}
func (b *backend) pathImportKey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// data.Raw should be map[string]interface{}
	for _, v := range data.Raw {
		// k is the field of the key
		// v is the json representation of a string
		jSonKeyset := fmt.Sprintf("%s", v)

		// is the json a valid key
		_, err := aeadutils.ValidateKeySetJson(jSonKeyset)
		if err != nil {
			hclog.L().Error("pathImportKey Invaid Json as key", err.Error())
			return &logical.Response{
				Data: make(map[string]interface{}),
			}, err
		}
	}
	// ok, its ALL valid, save it
	_, err := b.configWriteOverwriteCheck(ctx, req, data, true, true)
	if err != nil {
		hclog.L().Error("save key failed", err.Error())
		return &logical.Response{
			Data: make(map[string]interface{}),
		}, err
	}
	return &logical.Response{
		Data: data.Raw,
	}, nil
}

func (b *backend) pathAeadCreateDeterministicKeys(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.createDeterministicKeysOverwriteCheck(ctx, req, data, false)
}

func (b *backend) pathAeadCreateDeterministicKeysOverwrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.createDeterministicKeysOverwriteCheck(ctx, req, data, true)
}

func (b *backend) createDeterministicKeysOverwriteCheck(ctx context.Context, req *logical.Request, data *framework.FieldData, overwrite bool) (*logical.Response, error) {

	// retrieve the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	resp := make(map[string]interface{})
	var createdKeys []string
	var skippedKeys []string
	var failedKeys []map[string]string

	// Support two modes:
	// 1. New way: {"data": {"field1": "value", "field2": "value"}} - NO warnings
	// 2. Old way: {"field1": "value", "field2": "value"} - shows warnings (backward compat)
	var fieldsToProcess map[string]interface{}

	if dataParam := data.Get("data"); dataParam != nil {
		// New way: data is wrapped in "data" field
		if dataMap, ok := dataParam.(map[string]interface{}); ok {
			fieldsToProcess = dataMap
		} else {
			return nil, fmt.Errorf("'data' field must be a map of key-value pairs")
		}
	} else {
		// Old way: backward compatibility - use data.Raw directly
		fieldsToProcess = data.Raw
	}

	// iterate through the key=value supplied (ie field1=myaddress field2=myphonenumber)
	for fieldName, unencryptedData := range fieldsToProcess {

		// create new DAEAD key
		keysetHandle, tinkDetAead, err := aeadutils.CreateNewDeterministicAead()
		if err != nil {
			hclog.L().Error("Failed to create a new key", err)
			failedKeys = append(failedKeys, map[string]string{
				"key":   fieldName,
				"error": "failed to create key: " + err.Error(),
			})
			continue
		}

		if !overwrite {
			// don't do this if we already have a key in the config - prevents overwrite
			// get the prefix dynamically based on the key type
			prefix := aeadutils.GetKeyPrefix(fieldName, "", keysetHandle)
			_, ok := AEAD_CONFIG.Get(prefix + fieldName)
			if ok {
				skippedKeys = append(skippedKeys, fieldName)
				continue
			}
		}
		// set additionalDataBytes as field name of the right type
		additionalDataBytes := []byte(fieldName)

		// set the unencrypted data to be the right type
		unencryptedDataBytes := []byte(fmt.Sprintf("%v", unencryptedData))

		// encrypt the data into cypherText (cyphertext)
		cypherText, err := tinkDetAead.EncryptDeterministically(unencryptedDataBytes, additionalDataBytes)
		if err != nil {
			hclog.L().Error("Failed to encrypt with a new key", err)
			failedKeys = append(failedKeys, map[string]string{
				"key":   fieldName,
				"error": "failed to encrypt: " + err.Error(),
			})
			continue
		}

		// set the response as the base64 encrypted data
		resp[fieldName] = b64.StdEncoding.EncodeToString(cypherText)

		// extract the key that could be stored, do not overwrite
		b.saveKeyToConfig(keysetHandle, fieldName, ctx, req, true)
		createdKeys = append(createdKeys, fieldName)
	}

	// Add summary statistics
	resp["summary"] = map[string]interface{}{
		"created_keys": len(createdKeys),
		"skipped_keys": len(skippedKeys),
		"failed_keys":  len(failedKeys),
	}
	if len(createdKeys) > 0 {
		resp["created_list"] = createdKeys
	}
	if len(skippedKeys) > 0 {
		resp["skipped_list"] = skippedKeys
	}
	if len(failedKeys) > 0 {
		resp["failed_list"] = failedKeys
	}

	return &logical.Response{
		Data: resp,
	}, nil
}
func (b *backend) pathAeadCreateNonDeterministicKeys(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.createNonDeterministicKeysOverwriteCheck(ctx, req, data, false)
}

func (b *backend) pathAeadCreateNonDeterministicKeysOverwrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.createNonDeterministicKeysOverwriteCheck(ctx, req, data, true)
}

func (b *backend) createNonDeterministicKeysOverwriteCheck(ctx context.Context, req *logical.Request, data *framework.FieldData, overwrite bool) (*logical.Response, error) {

	// retrieve the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	resp := make(map[string]interface{})
	var createdKeys []string
	var skippedKeys []string
	var failedKeys []map[string]string

	// Support two modes:
	// 1. New way: {"data": {"field1": "value", "field2": "value"}} - NO warnings
	// 2. Old way: {"field1": "value", "field2": "value"} - shows warnings (backward compat)
	var fieldsToProcess map[string]interface{}

	if dataParam := data.Get("data"); dataParam != nil {
		// New way: data is wrapped in "data" field
		if dataMap, ok := dataParam.(map[string]interface{}); ok {
			fieldsToProcess = dataMap
		} else {
			return nil, fmt.Errorf("'data' field must be a map of key-value pairs")
		}
	} else {
		// Old way: backward compatibility - use data.Raw directly
		fieldsToProcess = data.Raw
	}

	// iterate through the key=value supplied (ie field1=myaddress field2=myphonenumber)
	for fieldName, unencryptedData := range fieldsToProcess {

		// create new AEAD key
		keysetHandle, tinkAead, err := aeadutils.CreateNewAead()
		if err != nil {
			hclog.L().Error("Failed to create a new key", err)
			failedKeys = append(failedKeys, map[string]string{
				"key":   fieldName,
				"error": "failed to create key: " + err.Error(),
			})
			continue
		}

		if !overwrite {
			// don't do this if we already have a key in the config - prevents overwrite
			// get the prefix dynamically based on the key type
			prefix := aeadutils.GetKeyPrefix(fieldName, "", keysetHandle)
			_, ok := AEAD_CONFIG.Get(prefix + fieldName)
			if ok {
				skippedKeys = append(skippedKeys, fieldName)
				continue
			}
		}
		// set additionalDataBytes as field name of the right type
		additionalDataBytes := []byte(fieldName)

		// set the unencrypted data to be the right type
		unencryptedDataBytes := []byte(fmt.Sprintf("%v", unencryptedData))

		// encrypt the data into cypherText (cyphertext)
		cypherText, err := tinkAead.Encrypt(unencryptedDataBytes, additionalDataBytes)
		if err != nil {
			hclog.L().Error("Failed to encrypt with a new key", err)
			failedKeys = append(failedKeys, map[string]string{
				"key":   fieldName,
				"error": "failed to encrypt: " + err.Error(),
			})
			continue
		}

		// set the response as the base64 encrypted data
		resp[fieldName] = b64.StdEncoding.EncodeToString(cypherText)

		// extract the key that could be stored, do not overwrite
		b.saveKeyToConfig(keysetHandle, fieldName, ctx, req, true)
		createdKeys = append(createdKeys, fieldName)
	}

	// Add summary statistics
	resp["summary"] = map[string]interface{}{
		"created_keys": len(createdKeys),
		"skipped_keys": len(skippedKeys),
		"failed_keys":  len(failedKeys),
	}
	if len(createdKeys) > 0 {
		resp["created_list"] = createdKeys
	}
	if len(skippedKeys) > 0 {
		resp["skipped_list"] = skippedKeys
	}
	if len(failedKeys) > 0 {
		resp["failed_list"] = failedKeys
	}

	return &logical.Response{
		Data: resp,
	}, nil
}

func (b *backend) saveKeyToConfig(keysetHandle *keyset.Handle, fieldName string, ctx context.Context, req *logical.Request, overwrite bool) {

	prefix := aeadutils.GetKeyPrefix(fieldName, "", keysetHandle)
	fieldName = prefix + fieldName

	// retrieve the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return
	}

	if !overwrite {
		// don't do this if we already have a key in the config - prevents overwrite
		_, ok := AEAD_CONFIG.Get(fieldName)
		if ok {
			hclog.L().Error("saveKeyToConfig - key already exists " + fieldName)
			return
		}
	}
	// extract the key that could be stored
	// save the new key into config
	keyAsJson, err := aeadutils.ExtractInsecureKeySetFromKeyhandle(keysetHandle)
	if err != nil {
		hclog.L().Error("Failed to save to config", err)
	}

	AEAD_CONFIG.Set(fieldName, keyAsJson)

	m1 := make(map[string]interface{})
	m1[fieldName] = keyAsJson

	// prior to this there were race conditions as multiple goroutines access data
	dn := framework.FieldData{
		//		Raw:    AEAD_CONFIG.Items(),
		Raw:    m1,
		Schema: nil,
	}
	if overwrite {
		b.pathConfigOverwrite(ctx, req, &dn)
	} else {
		b.pathConfigWrite(ctx, req, &dn)
	}
}

func (b *backend) getAdditionalData(fieldName string, config cmap.ConcurrentMap) []byte {

	// set additionalDataBytes as field name of the right type
	aad, ok := AEAD_CONFIG.Get("ADDITIONAL_DATA_" + fieldName)
	if ok {
		aadStr := fmt.Sprintf("%s", aad)
		return []byte(aadStr)
	}

	return []byte(fieldName)
}
