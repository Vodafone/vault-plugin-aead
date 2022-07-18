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

var aeadConfig = cmap.New()

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.configWriteOverwriteCheck(ctx, req, data, false)
}
func (b *backend) pathConfigOverwrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.configWriteOverwriteCheck(ctx, req, data, true)

}
func (b *backend) configWriteOverwriteCheck(ctx context.Context, req *logical.Request, data *framework.FieldData, overwrite bool) (*logical.Response, error) {

	if err := data.Validate(); err != nil {
		return nil, logical.CodedError(422, err.Error())
	}

	// iterate through the supplied map, adding it to the config map
	for k, v := range data.Raw {
		if !overwrite {
			// don't do this if we already have a key in the config - prevents overwrite
			_, ok := aeadConfig.Get(k)
			if ok {
				hclog.L().Info("pathConfigWrite - key already exists " + k)
				continue
			}
		}
		aeadConfig.Set(k, v)
	}

	entry, err := logical.StorageEntryJSON("config", aeadConfig)
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
		aeadConfig.Remove(k)
		// err := req.Storage.Delete(ctx, k)
		// if err != nil {
		// 	hclog.L().Error("failed to delete config")
		// 	return nil, fmt.Errorf("failed to delete config: %w", err)
		// }
	}

	entry, err := logical.StorageEntryJSON("config", aeadConfig)
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
	result := make(map[string]interface{}, len(aeadConfig.Items()))
	for k, v := range aeadConfig.Items() {
		if isEncryptionJsonKey(v.(string)) {
			v = muteKeyMaterial(v.(string))
		}
		result[k] = v
	}
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
	for k, v := range aeadConfig.Items() {
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

func (b *backend) config(ctx context.Context, s logical.Storage) (map[string]interface{}, error) {

	config := make(map[string]interface{})
	entry, err := s.Get(ctx, "config")

	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	if err := entry.DecodeJSON(&config); err != nil {
		return nil, err
	}
	return config, nil
}

func (b *backend) pathKeyRotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}
	for keyField, encryptionKey := range aeadConfig.Items() {
		fieldName := fmt.Sprintf("%v", keyField)
		keyStr := fmt.Sprintf("%v", encryptionKey)
		if !isEncryptionJsonKey(keyStr) {
			// aeadConfig.Set(keyFieldStr, encryptionKey)
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

	entry, err := logical.StorageEntryJSON("config", aeadConfig)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathUpdateKeyStatus(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// data.Raw is map[string]map[string]string
	// map['field0':map['key':'status']]

	resp := make(map[string]interface{})

	for fieldName, v := range data.Raw {
		// GET THE KEY
		encryptionkey, ok := aeadConfig.Get(fieldName)
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

	return &logical.Response{
		Data: resp,
	}, nil
}
func (b *backend) pathUpdateKeyMaterial(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// data.Raw is map[string]map[string]string
	// map['field0':map['key':'material']]

	resp := make(map[string]interface{})

	for fieldName, v := range data.Raw {
		// GET THE KEY
		encryptionkey, ok := aeadConfig.Get(fieldName)
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
		if isEncryptionJsonKey(v.(string)) {
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

	resp := make(map[string]interface{})

	for fieldName, v := range data.Raw {
		// GET THE KEY
		encryptionkey, ok := aeadConfig.Get(fieldName)
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

	return &logical.Response{
		Data: resp,
	}, nil
}
func (b *backend) pathUpdateKeyID(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// data.Raw is map[string]map[string]string
	// map['field0':map['key':'newkey']]

	resp := make(map[string]interface{})

	for fieldName, v := range data.Raw {
		// GET THE KEY
		encryptionkey, ok := aeadConfig.Get(fieldName)
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

	return &logical.Response{
		Data: resp,
	}, nil
}
func (b *backend) pathImportKey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// data.Raw should be map[string]interface{}
	for _, v := range data.Raw {
		// k is the field of the key
		// v is the json representation of a string
		jSonKeyset := fmt.Sprintf("%s", v)

		// is the json a valid key
		err := ValidateKeySetJson(jSonKeyset)
		if err != nil {
			hclog.L().Error("pathImportKey Invaid Json as key", err.Error())
			return &logical.Response{
				Data: make(map[string]interface{}),
			}, err
		}
	}
	// ok, its ALL valid, save it
	_, err := b.configWriteOverwriteCheck(ctx, req, data, true)
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
			_, ok := aeadConfig.Get(fieldName)
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
			_, ok := aeadConfig.Get(fieldName)
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

	if !overwrite {
		// don't do this if we already have a key in the config - prevents overwrite
		_, ok := aeadConfig.Get(fieldName)
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

	aeadConfig.Set(fieldName, keyAsJson)

	m1 := make(map[string]interface{})
	m1[fieldName] = keyAsJson

	// prior to this there were race conditions as multiple goroutines access data
	dn := framework.FieldData{
		//		Raw:    aeadConfig.Items(),
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
	aad, ok := aeadConfig.Get("ADDITIONAL_DATA_" + fieldName)
	if ok {
		aadStr := fmt.Sprintf("%s", aad)
		return []byte(aadStr)
	}

	return []byte(fieldName)
}
