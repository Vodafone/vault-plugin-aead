package aeadplugin

import (
	"bytes"
	"context"
	b64 "encoding/base64"
	"fmt"

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

	// hclog.L().Info("mountpoint - " + req.MountPoint)
	// fmt.Printf("\nmountpoint - %s", req.MountPoint)

	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	// iterate through the supplied map, adding it to the config map
	for k, v := range data.Raw {

		prefix := GetKeyPrefix(k, fmt.Sprintf("%v", v), nil)
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

	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	// iterate through the supplied map, deleting from the store
	for k, _ := range data.Raw {
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

	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}
	result := make(map[string]interface{}, len(AEAD_CONFIG.Items()))
	for k, v := range AEAD_CONFIG.Items() {
		_, err := ValidateKeySetJson(v.(string))
		if err != nil {
			v = muteKeyMaterial(v.(string))
		}
		result[k] = v
	}
	result["MountPoint"] = req.MountPoint
	return &logical.Response{
		Data: result,
	}, nil
}

func (b *backend) pathReadKeyTypes(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	m := map[string]interface{}{}
	for k, v := range AEAD_CONFIG.Items() {
		str := ""
		_, determinstic := isKeyJsonDeterministic(v)
		if determinstic {
			str = "DETERMINISTIC"
		} else {
			str = "NON DETERMINISTIC"
		}
		m[k] = str
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
	for k, _ := range AEAD_CONFIG.Items() {
		if _, ok := consulConfig[k]; !ok {
			AEAD_CONFIG.Remove(k)
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

func (b *backend) pathKeyRotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	for keyField, encryptionKey := range AEAD_CONFIG.Items() {
		fieldName := fmt.Sprintf("%v", keyField)
		keyStr := fmt.Sprintf("%v", encryptionKey)
		_, err := ValidateKeySetJson(keyStr)
		if err != nil {
			// not a valid key
			continue
		} else {
			encryptionKeyStr, deterministic := isKeyJsonDeterministic(encryptionKey)
			if deterministic {
				kh, _, err := CreateInsecureHandleAndDeterministicAead(encryptionKeyStr)
				if err != nil {
					hclog.L().Error("feiled to create key handlep")
					return &logical.Response{
						Data: make(map[string]interface{}),
					}, nil
				}
				RotateKeys(kh, true)
				b.saveKeyToConfig(kh, fieldName, ctx, req, true)
			} else {
				kh, _, err := CreateInsecureHandleAndAead(encryptionKeyStr)
				if err != nil {
					hclog.L().Error("feiled to create key handlep")
					return &logical.Response{
						Data: make(map[string]interface{}),
					}, nil
				}
				RotateKeys(kh, false)
				b.saveKeyToConfig(kh, fieldName, ctx, req, true)
			}
		}
	}

	// TODO poss not needed
	// entry, err := logical.StorageEntryJSON("config", AEAD_CONFIG)
	// if err != nil {
	// 	return nil, err
	// }

	// if err := req.Storage.Put(ctx, entry); err != nil {
	// 	return nil, err
	// }

	return nil, nil
}

func (b *backend) pathUpdateKeyStatus(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// data.Raw is map[string]map[string]string
	// map['field0':map['key':'status']]
	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	resp := make(map[string]interface{})

	for fieldName, v := range data.Raw {
		// GET THE KEY
		encryptionkey, ok := getEncryptionKey(fieldName)
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

			// update the status, get a new heyhandle
			newKh, err := UpdateKeyStatus(kh, keyId, statusStr)
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
		_, err := ValidateKeySetJson(v.(string))
		if err == nil {
			// we do have a valid key
			v = muteKeyMaterial(v.(string))
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
	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}
	resp := make(map[string]interface{})

	for fieldName, v := range data.Raw {
		// GET THE KEY
		encryptionkey, ok := getEncryptionKey(fieldName)

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

			// update the status, get a new heyhandle
			newKh, err := UpdateKeyMaterial(kh, keyId, materialStr)
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
		_, err := ValidateKeySetJson(v.(string))
		if err != nil {
			// valid key
			v = muteKeyMaterial(v.(string))
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
	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}
	resp := make(map[string]interface{})

	for fieldName, v := range data.Raw {
		// GET THE KEY
		encryptionkey, ok := getEncryptionKey(fieldName)

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

		// update the status, get a new heyhandle
		newKh, err := UpdatePrimaryKeyID(kh, newPrimaryKeyStr)
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
		_, err := ValidateKeySetJson(v.(string))
		if err != nil {
			// valid key
			v = muteKeyMaterial(v.(string))
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
	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}
	resp := make(map[string]interface{})

	for fieldName, v := range data.Raw {
		// GET THE KEY
		encryptionkey, ok := getEncryptionKey(fieldName)

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

			// update the status, get a new heyhandle
			newKh, err := UpdateKeyID(kh, keyId, newKeyStr)
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
		_, err := ValidateKeySetJson(v.(string))
		if err != nil {
			// valid key
			v = muteKeyMaterial(v.(string))
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
		_, err := ValidateKeySetJson(jSonKeyset)
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

	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	resp := make(map[string]interface{})

	// iterate through the key=value supplied (ie field1=myaddress field2=myphonenumber)
	for fieldName, unencryptedData := range data.Raw {

		if !overwrite {
			// don't do this if we already have a key in the config - prevents overwrite
			_, ok := AEAD_CONFIG.Get(fieldName)
			if ok {
				resp[fieldName] = fieldName + " key exists"
				continue
			}
		}

		// create new DAEAD key
		keysetHandle, tinkDetAead, err := CreateNewDeterministicAead()
		if err != nil {
			hclog.L().Error("Failed to create a new key", err)
			return &logical.Response{
				Data: resp,
			}, err
		}
		// set additionalDataBytes as field name of the right type
		additionalDataBytes := []byte(fieldName)

		// set the unencrypted data to be the right type
		unencryptedDataBytes := []byte(fmt.Sprintf("%v", unencryptedData))

		// encrypt the data into cypherText (cyphertext)
		cypherText, err := tinkDetAead.EncryptDeterministically(unencryptedDataBytes, additionalDataBytes)
		if err != nil {
			hclog.L().Error("Failed to encrypt with a new key", err)
			return &logical.Response{
				Data: resp,
			}, err
		}

		// set the response as the base64 encrypted data
		resp[fieldName] = b64.StdEncoding.EncodeToString(cypherText)

		// extract the key that could be stored, do not overwrite
		b.saveKeyToConfig(keysetHandle, fieldName, ctx, req, true)
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

	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	resp := make(map[string]interface{})

	// iterate through the key=value supplied (ie field1=myaddress field2=myphonenumber)
	for fieldName, unencryptedData := range data.Raw {

		if !overwrite {
			// don't do this if we already have a key in the config - prevents overwrite
			_, ok := AEAD_CONFIG.Get(fieldName)
			if ok {
				resp[fieldName] = fieldName + " key exists"
				continue
			}
		}

		// create new DAEAD key
		keysetHandle, tinkAead, err := CreateNewAead()
		if err != nil {
			hclog.L().Error("Failed to create a new key", err)
			return &logical.Response{
				Data: resp,
			}, err
		}
		// set additionalDataBytes as field name of the right type
		additionalDataBytes := []byte(fieldName)

		// set the unencrypted data to be the right type
		unencryptedDataBytes := []byte(fmt.Sprintf("%v", unencryptedData))

		// encrypt the data into cypherText (cyphertext)
		cypherText, err := tinkAead.Encrypt(unencryptedDataBytes, additionalDataBytes)
		if err != nil {
			hclog.L().Error("Failed to encrypt with a new key", err)
			return &logical.Response{
				Data: resp,
			}, err
		}

		// set the response as the base64 encrypted data
		resp[fieldName] = b64.StdEncoding.EncodeToString(cypherText)

		// extract the key that could be stored, do not overwrite
		b.saveKeyToConfig(keysetHandle, fieldName, ctx, req, true)
	}

	return &logical.Response{
		Data: resp,
	}, nil
}

func (b *backend) saveKeyToConfig(keysetHandle *keyset.Handle, fieldName string, ctx context.Context, req *logical.Request, overwrite bool) {

	prefix := GetKeyPrefix(fieldName, "", keysetHandle)
	fieldName = prefix + fieldName

	// retrive the config from  storage
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
	keyAsJson, err := ExtractInsecureKeySetFromKeyhandle(keysetHandle)
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
