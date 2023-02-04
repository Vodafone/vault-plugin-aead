package aeadplugin

import (
	"bytes"
	"context"
	b64 "encoding/base64"
	"fmt"
	"strconv"
	"time"

	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	cmap "github.com/orcaman/concurrent-map"
	"go.opentelemetry.io/otel"
)

var AEAD_CONFIG = cmap.New()
var AEAD_KEYS = cmap.New()

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	initialiseOpenTel()
	tr := tp.Tracer("pathConfigWrite-tracer")

	ctx, span := tr.Start(ctx, "pathConfigWrite")
	defer func() {
		span.End()
		if err := tp.Shutdown(ctx); err != nil {
			hclog.L().Error("Failed to shutdown tracerProvider", err)
		}
	}()
	return b.configWriteOverwriteCheck(ctx, req, data, false)
}
func (b *backend) pathConfigOverwrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	initialiseOpenTel()
	tr := tp.Tracer("pathConfigOverwrite-tracer")

	ctx, span := tr.Start(ctx, "pathConfigOverwrite")
	defer func() {
		span.End()
		if err := tp.Shutdown(ctx); err != nil {
			hclog.L().Error("Failed to shutdown tracerProvider", err)
		}
	}()
	return b.configWriteOverwriteCheck(ctx, req, data, true)
}
func (b *backend) configWriteOverwriteCheck(ctx context.Context, req *logical.Request, data *framework.FieldData, overwrite bool) (*logical.Response, error) {
	tr := otel.Tracer("component-configWriteOverwriteCheck")
	_, span := tr.Start(ctx, "configWriteOverwriteCheck")
	defer span.End()

	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	// iterate through the supplied map, adding it to the config map
	for k, v := range data.Raw {
		if !overwrite {
			// don't do this if we already have a key in the config - prevents overwrite
			_, ok := AEAD_CONFIG.Get(k)
			if ok {
				hclog.L().Info("pathConfigWrite - key already exists " + k)
				continue
			}
		}
		AEAD_CONFIG.Set(k, v)
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
	initialiseOpenTel()
	tr := tp.Tracer("pathConfigDelete-tracer")

	ctx, span := tr.Start(ctx, "pathConfigDelete")
	defer func() {
		span.End()
		if err := tp.Shutdown(ctx); err != nil {
			hclog.L().Error("Failed to shutdown tracerProvider", err)
		}
	}()
	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	// iterate through the supplied map, deleting from the store
	for k, _ := range data.Raw {
		AEAD_CONFIG.Remove(k)
		// err := req.Storage.Delete(ctx, k)
		// if err != nil {
		// 	hclog.L().Error("failed to delete config")
		// 	return nil, fmt.Errorf("failed to delete config: %w", err)
		// }
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
	initialiseOpenTel()
	tr := tp.Tracer("pathConfigRead-tracer")

	ctx, span := tr.Start(ctx, "pathConfigRead")
	defer func() {
		span.End()
		if err := tp.Shutdown(ctx); err != nil {
			hclog.L().Error("Failed to shutdown tracerProvider", err)
		}
	}()
	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}
	result := make(map[string]interface{}, len(AEAD_CONFIG.Items()))
	for k, v := range AEAD_CONFIG.Items() {
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
	initialiseOpenTel()
	tr := tp.Tracer("pathReadKeyTypes-tracer")

	ctx, span := tr.Start(ctx, "pathReadKeyTypes")
	defer func() {
		span.End()
		if err := tp.Shutdown(ctx); err != nil {
			hclog.L().Error("Failed to shutdown tracerProvider", err)
		}
	}()
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

func (b *backend) getAeadConfig(ctx context.Context, req *logical.Request, b_optionalDirtyRead ...bool) error {
	tr := otel.Tracer("component-getAeadConfig")
	_, span := tr.Start(ctx, "getAeadConfig")
	defer span.End()

	hclog.L().Info("getAeadConfig start AEAD_LENGTH=" + strconv.Itoa(len(AEAD_CONFIG.Items())))

	dirtyRead := false
	if len(b_optionalDirtyRead) > 0 {
		dirtyRead = b_optionalDirtyRead[0]
	}

	// if we are doing a dirty read and the config is not empty then return, don't bother re-reading
	if dirtyRead && !AEAD_CONFIG.IsEmpty() {
		return nil
	}

	t := time.Now()
	consulConfig, err := b.readConsulConfig(ctx, req.Storage)
	hclog.L().Info("getAeadConfig time to read Consul=" + time.Since(t).String())
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
	hclog.L().Info("getAeadConfig end AEAD_LENGTH=" + strconv.Itoa(len(AEAD_CONFIG.Items())))

	return nil
}

func (b *backend) readConsulConfig(ctx context.Context, s logical.Storage) (map[string]interface{}, error) {
	tr := otel.Tracer("component-readConsulConfig")
	_, span := tr.Start(ctx, "readConsulConfig")
	defer span.End()

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
	initialiseOpenTel()
	tr := tp.Tracer("pathKeyRotate-tracer")

	ctx, span := tr.Start(ctx, "pathKeyRotate")
	defer func() {
		span.End()
		if err := tp.Shutdown(ctx); err != nil {
			hclog.L().Error("Failed to shutdown tracerProvider", err)
		}
	}()
	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	for keyField, encryptionKey := range AEAD_CONFIG.Items() {
		fieldName := fmt.Sprintf("%v", keyField)
		keyStr := fmt.Sprintf("%v", encryptionKey)
		if !isEncryptionJsonKey(keyStr) {
			// AEAD_CONFIG.Set(keyFieldStr, encryptionKey)
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

	entry, err := logical.StorageEntryJSON("config", AEAD_CONFIG)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathUpdateKeyStatus(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	initialiseOpenTel()
	tr := tp.Tracer("pathUpdateKeyStatus-tracer")

	ctx, span := tr.Start(ctx, "pathUpdateKeyStatus")
	defer func() {
		span.End()
		if err := tp.Shutdown(ctx); err != nil {
			hclog.L().Error("Failed to shutdown tracerProvider", err)
		}
	}()
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
		encryptionkey, ok := AEAD_CONFIG.Get(fieldName)
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
		if isEncryptionJsonKey(v.(string)) {
			v = muteKeyMaterial(v.(string))
		}
		mutedResult[k] = v
	}

	return &logical.Response{
		Data: mutedResult,
	}, nil
}
func (b *backend) pathUpdateKeyMaterial(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	initialiseOpenTel()
	tr := tp.Tracer("pathUpdateKeyMaterial-tracer")

	ctx, span := tr.Start(ctx, "pathUpdateKeyMaterial")
	defer func() {
		span.End()
		if err := tp.Shutdown(ctx); err != nil {
			hclog.L().Error("Failed to shutdown tracerProvider", err)
		}
	}()
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
		encryptionkey, ok := AEAD_CONFIG.Get(fieldName)
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
	initialiseOpenTel()
	tr := tp.Tracer("pathUpdatePrimaryKeyID-tracer")

	ctx, span := tr.Start(ctx, "pathUpdatePrimaryKeyID")
	defer func() {
		span.End()
		if err := tp.Shutdown(ctx); err != nil {
			hclog.L().Error("Failed to shutdown tracerProvider", err)
		}
	}()
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
		encryptionkey, ok := AEAD_CONFIG.Get(fieldName)
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
		if isEncryptionJsonKey(v.(string)) {
			v = muteKeyMaterial(v.(string))
		}
		mutedResult[k] = v
	}

	return &logical.Response{
		Data: mutedResult,
	}, nil
}
func (b *backend) pathUpdateKeyID(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	initialiseOpenTel()
	tr := tp.Tracer("pathUpdateKeyID-tracer")

	ctx, span := tr.Start(ctx, "pathUpdateKeyID")
	defer func() {
		span.End()
		if err := tp.Shutdown(ctx); err != nil {
			hclog.L().Error("Failed to shutdown tracerProvider", err)
		}
	}()
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
		encryptionkey, ok := AEAD_CONFIG.Get(fieldName)
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
		if isEncryptionJsonKey(v.(string)) {
			v = muteKeyMaterial(v.(string))
		}
		mutedResult[k] = v
	}

	return &logical.Response{
		Data: mutedResult,
	}, nil
}
func (b *backend) pathImportKey(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	initialiseOpenTel()
	tr := tp.Tracer("pathImportKey-tracer")

	ctx, span := tr.Start(ctx, "pathImportKey")
	defer func() {
		span.End()
		if err := tp.Shutdown(ctx); err != nil {
			hclog.L().Error("Failed to shutdown tracerProvider", err)
		}
	}()
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
	initialiseOpenTel()
	tr := tp.Tracer("pathAeadCreateDeterministicKeys-tracer")

	ctx, span := tr.Start(ctx, "pathAeadCreateDeterministicKeys")
	defer func() {
		span.End()
		if err := tp.Shutdown(ctx); err != nil {
			hclog.L().Error("Failed to shutdown tracerProvider", err)
		}
	}()
	return b.createDeterministicKeysOverwriteCheck(ctx, req, data, false)
}

func (b *backend) pathAeadCreateDeterministicKeysOverwrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	initialiseOpenTel()
	tr := tp.Tracer("pathAeadCreateDeterministicKeysOverwrite-tracer")

	ctx, span := tr.Start(ctx, "pathAeadCreateDeterministicKeysOverwrite")
	defer func() {
		span.End()
		if err := tp.Shutdown(ctx); err != nil {
			hclog.L().Error("Failed to shutdown tracerProvider", err)
		}
	}()
	return b.createDeterministicKeysOverwriteCheck(ctx, req, data, true)
}

func (b *backend) createDeterministicKeysOverwriteCheck(ctx context.Context, req *logical.Request, data *framework.FieldData, overwrite bool) (*logical.Response, error) {
	tr := otel.Tracer("component-createDeterministicKeysOverwriteCheck")
	_, span := tr.Start(ctx, "createDeterministicKeysOverwriteCheck")
	defer span.End()

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
	initialiseOpenTel()
	tr := tp.Tracer("pathAeadCreateNonDeterministicKeys-tracer")

	ctx, span := tr.Start(ctx, "pathAeadCreateNonDeterministicKeys")
	defer func() {
		span.End()
		if err := tp.Shutdown(ctx); err != nil {
			hclog.L().Error("Failed to shutdown tracerProvider", err)
		}
	}()
	return b.createNonDeterministicKeysOverwriteCheck(ctx, req, data, false)
}

func (b *backend) pathAeadCreateNonDeterministicKeysOverwrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	initialiseOpenTel()
	tr := tp.Tracer("pathAeadCreateNonDeterministicKeysOverwrite-tracer")

	ctx, span := tr.Start(ctx, "pathAeadCreateNonDeterministicKeysOverwrite")
	defer func() {
		span.End()
		if err := tp.Shutdown(ctx); err != nil {
			hclog.L().Error("Failed to shutdown tracerProvider", err)
		}
	}()
	return b.createNonDeterministicKeysOverwriteCheck(ctx, req, data, true)
}

func (b *backend) createNonDeterministicKeysOverwriteCheck(ctx context.Context, req *logical.Request, data *framework.FieldData, overwrite bool) (*logical.Response, error) {

	tr := otel.Tracer("component-createNonDeterministicKeysOverwriteCheck")
	_, span := tr.Start(ctx, "createNonDeterministicKeysOverwriteCheck")
	defer span.End()

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

	tr := otel.Tracer("component-saveKeyToConfig")
	_, span := tr.Start(ctx, "saveKeyToConfig")
	defer span.End()

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

func (b *backend) getAdditionalData(ctx context.Context, fieldName string, config cmap.ConcurrentMap) []byte {

	tr := otel.Tracer("component-getAdditionalData")
	_, span := tr.Start(ctx, "getAdditionalData")
	defer span.End()

	// set additionalDataBytes as field name of the right type
	aad, ok := AEAD_CONFIG.Get("ADDITIONAL_DATA_" + fieldName)
	if ok {
		aadStr := fmt.Sprintf("%s", aad)
		return []byte(aadStr)
	}

	return []byte(fieldName)
}

func getEncryptionKey(fieldName string, setDepth ...int) (interface{}, bool) {
	maxDepth := 5
	if len(setDepth) > 0 {
		maxDepth = setDepth[0]
	}
	possiblyEncryptionKey, ok := AEAD_CONFIG.Get(fieldName)
	if !ok {
		return nil, ok
	}
	for i := 1; i < maxDepth; i++ {
		possiblyEncryptionKeyStr := possiblyEncryptionKey.(string)
		if !isEncryptionJsonKey(possiblyEncryptionKeyStr) {
			possiblyEncryptionKey, ok = AEAD_CONFIG.Get(possiblyEncryptionKeyStr)
			if !ok {
				return nil, ok
			}
		} else {
			return possiblyEncryptionKey, true
		}
	}

	isKeysetFound := false
	return nil, isKeysetFound
}

func (b *backend) getKeyAndAD(fieldName string, ctx context.Context, req *logical.Request) (interface{}, []byte, error) {

	tr := otel.Tracer("component-getKeyAndAD")
	_, span := tr.Start(ctx, "getKeyAndAD")
	defer span.End()

	t := time.Now()
	hclog.L().Info("getKeyAndAD AEAD_LENGTH=" + strconv.Itoa(len(AEAD_CONFIG.Items())))

	// retrive the config from  storage with a dirty read
	err := b.getAeadConfig(ctx, req, true)
	if err != nil {
		return nil, nil, err
	}
	hclog.L().Info("getKeyAndAD re-read config time to read =" + time.Since(t).String() + " AEAD_LENGTH=" + strconv.Itoa(len(AEAD_CONFIG.Items())))
	t = time.Now()

	// set additionalDataBytes as field name of the right type
	additionalDataBytes := b.getAdditionalData(ctx, fieldName, AEAD_CONFIG)

	_, ok := AEAD_CONFIG.Get("DIRTY_READ_KEYS")
	if ok {
		tinkKeySet, ok := AEAD_KEYS.Get(fieldName)
		if ok {
			hclog.L().Info("getKeyAndAD FOUND KEY IN AEAD_KEYS for FIELD=" + fieldName + " time to read =" + time.Since(t).String())
			return tinkKeySet, additionalDataBytes, nil
		}
		hclog.L().Info("getKeyAndAD NOT FOUND KEY IN AEAD_KEYS for FIELD=" + fieldName + " time to read =" + time.Since(t).String())

	}
	t = time.Now()

	encryptionkeyIntf, ok := getEncryptionKey(fieldName)

	// do we have a key already in config
	if ok {
		// is the key we have retrived deterministic?
		encryptionKeyStr, deterministic := isKeyJsonDeterministic(encryptionkeyIntf)
		if deterministic {
			// SUPPORT FOR DETERMINISTIC AEAD
			// we don't need the key handle which is returned first
			_, tinkDetAead, err := CreateInsecureHandleAndDeterministicAead(encryptionKeyStr)
			if err != nil {
				hclog.L().Error("getKeyAndAD Failed to create a keyhandle time="+time.Since(t).String(), err)
				return nil, nil, err
			} else {
				b.saveKeyObjectToConfig(fieldName, tinkDetAead, ctx, req)
				hclog.L().Info("getKeyAndAD FOUND KEY IN CONFIG for FIELD=" + fieldName + " time to read Consul=" + time.Since(t).String())
				return tinkDetAead, additionalDataBytes, nil
			}
		} else {
			_, tinkAead, err := CreateInsecureHandleAndAead(encryptionKeyStr)
			if err != nil {
				hclog.L().Error("getKeyAndAD Failed to create a keyhandle time="+time.Since(t).String(), err)
				return nil, nil, err
			} else {
				b.saveKeyObjectToConfig(fieldName, tinkAead, ctx, req)
				hclog.L().Info("getKeyAndAD FOUND KEY IN CONFIG for FIELD=" + fieldName + " time to read Consul=" + time.Since(t).String())
				return tinkAead, additionalDataBytes, nil
			}
		}
	}
	hclog.L().Error("getKeyAndAD Failed to find or create a key time=" + time.Since(t).String())
	return nil, nil, nil
}

func (b *backend) saveKeyObjectToConfig(fieldName string, keyObj interface{}, ctx context.Context, req *logical.Request) {

	tr := otel.Tracer("component-saveKeyObjectToConfig")
	_, span := tr.Start(ctx, "saveKeyObjectToConfig")
	defer span.End()

	AEAD_KEYS.Set(fieldName, keyObj)
}
