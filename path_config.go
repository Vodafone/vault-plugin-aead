package aeadplugin

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/bigquery"
	kms "cloud.google.com/go/kms/apiv1"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	cmap "github.com/orcaman/concurrent-map"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

var aeadConfig = cmap.New()

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathConfigWriteOverwriteCheck(ctx, req, data, false)
}
func (b *backend) pathConfigOverwrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathConfigWriteOverwriteCheck(ctx, req, data, true)

}
func (b *backend) pathConfigWriteOverwriteCheck(ctx context.Context, req *logical.Request, data *framework.FieldData, overwrite bool) (*logical.Response, error) {

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

	// iterate through the supplied map, deleting from the store
	for k, _ := range data.Raw {
		req.Storage.Delete(ctx, k)
	}

	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: aeadConfig.Items(),
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
		if !strings.Contains(keyStr, "primaryKeyId") {
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
				saveKeyToConfig(kh, fieldName, b, ctx, req, true)
			} else {
				kh, _, err := CreateInsecureHandleAndAead(encryptionKeyStr)
				if err != nil {
					hclog.L().Error("feiled to create key handlep")
					return &logical.Response{
						Data: make(map[string]interface{}),
					}, nil
				}
				RotateKeys(kh, false)
				saveKeyToConfig(kh, fieldName, b, ctx, req, true)
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

func (b *backend) pathKeySync(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}
	for keyField, encryptionKey := range aeadConfig.Items() {
		fieldName := fmt.Sprintf("%v", keyField)
		keyStr := fmt.Sprintf("%v", encryptionKey)
		if !strings.Contains(keyStr, "primaryKeyId") {
			continue
		} else {
			encryptionKeyStr, deterministic := isKeyJsonDeterministic(encryptionKey)
			if deterministic {
				kh, _, err := CreateInsecureHandleAndDeterministicAead(encryptionKeyStr)
				if err != nil {
					hclog.L().Error("failed to create deterministic key handle")
					return &logical.Response{
						Data: make(map[string]interface{}),
					}, err
				}
				doBQSync(kh, fieldName, true)
				// do deterministic sync
			} else {
				kh, _, err := CreateInsecureHandleAndAead(encryptionKeyStr)
				if err != nil {
					hclog.L().Error("failed to create non deterministic key handle")
					return &logical.Response{
						Data: make(map[string]interface{}),
					}, err
				}
				// do non- deterministic sync
				doBQSync(kh, fieldName, false)
			}
		}
	}

	return nil, nil
}

type Options struct {
	bigqueryProjectId string
	datasetId         string
	routineId         string
	kmsKeyName        string
}

func doBQSync(kh *keyset.Handle, fieldName string, deterministic bool) {
	// Specify the following values
	var options Options

	options.bigqueryProjectId = "vf-pf1-ca-live"
	options.datasetId = "pii_dataset_eu"
	if deterministic {
		options.routineId = "pii_daead_" + fieldName + "_"
	} else {
		options.routineId = "pii_aead_" + fieldName + "_"

	}
	options.kmsKeyName = "projects/vf-grp-shared-services-poc2/locations/europe/keyRings/tink-keyring/cryptoKeys/key1" // Format: 'projects/.../locations/.../keyRings/.../cryptoKeys/...'

	// 0. Initate clients
	ctx := context.Background()
	kmsClient, err := kms.NewKeyManagementClient(ctx)

	if err != nil {
		hclog.L().Error("failed to setup client:  %v", err)
	}
	defer kmsClient.Close()

	binaryKeyset := new(bytes.Buffer)
	insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(binaryKeyset))

	// 2. Wrap the binary keyset with KMS.

	encryptReq := &kmspb.EncryptRequest{
		Name:      options.kmsKeyName,
		Plaintext: binaryKeyset.Bytes(),
	}

	encryptResp, err := kmsClient.Encrypt(ctx, encryptReq)
	if err != nil {
		hclog.L().Error("Failed to encrypt keyset:  %v", err)
	}

	// 3. Format the wrapped keyset as an escaped bytestring (like '\x00\x01\xAD') so BQ can accept it.
	escapedWrappedKeyset := ""
	for _, cbyte := range encryptResp.Ciphertext {
		escapedWrappedKeyset += fmt.Sprintf("\\x%02x", cbyte)
	}

	doBQRoutineCreateOrUpdate(ctx, options, escapedWrappedKeyset, deterministic)

}

func doBQRoutineCreateOrUpdate(ctx context.Context, options Options, escapedWrappedKeyset string, deterministic bool) {

	bigqueryClient, err := bigquery.NewClient(ctx, options.bigqueryProjectId)
	if err != nil {
		hclog.L().Error("Failed to create a bigquery client:  %v", err)

	}
	defer bigqueryClient.Close()

	// 4. Create a BigQuery Routine. You'll likely want to create one Routine each for encryption/decryption.
	routineEncryptBody := fmt.Sprintf("AEAD.ENCRYPT(KEYS.KEYSET_CHAIN(\"gcp-kms://%s\", b\"%s\"), plaintext, aad)", options.kmsKeyName, escapedWrappedKeyset)
	if deterministic {
		routineEncryptBody = fmt.Sprintf("DETERMINISTIC_ENCRYPT(KEYS.KEYSET_CHAIN(\"gcp-kms://%s\", b\"%s\"), plaintext, aad)", options.kmsKeyName, escapedWrappedKeyset)
	}

	// a field name might have a "-" in it, but "-" are not allowed in BQ, so translate them to "_"
	tmp_routineId := options.routineId
	options.routineId = strings.Replace(tmp_routineId, "-", "_", -1)

	routineEncryptRef := bigqueryClient.Dataset(options.datasetId).Routine(options.routineId + "encrypt")
	routineExists := true
	rm, err := routineEncryptRef.Metadata(ctx)
	if err != nil {
		routineExists = false
	}

	if !routineExists {
		metadataEncrypt := &bigquery.RoutineMetadata{
			Type:     "SCALAR_FUNCTION",
			Language: "SQL",
			Body:     routineEncryptBody,
			Arguments: []*bigquery.RoutineArgument{
				{Name: "plaintext", DataType: &bigquery.StandardSQLDataType{TypeKind: "STRING"}},
				{Name: "aad", DataType: &bigquery.StandardSQLDataType{TypeKind: "STRING"}},
			},
		}
		err := routineEncryptRef.Create(ctx, metadataEncrypt)
		if err != nil {
			hclog.L().Error("Failed to create encrypt routine: %v errmessge=%s", err, err.Error())

		}
		hclog.L().Info("Encrypt Routine successfully created!", "info", nil)
	} else {
		metadataUpdatetoUpdate := &bigquery.RoutineMetadataToUpdate{
			Type:     "SCALAR_FUNCTION",
			Language: "SQL",
			Body:     routineEncryptBody,
			Arguments: []*bigquery.RoutineArgument{
				{Name: "plaintext", DataType: &bigquery.StandardSQLDataType{TypeKind: "STRING"}},
				{Name: "aad", DataType: &bigquery.StandardSQLDataType{TypeKind: "STRING"}},
			},
		}
		_, err = routineEncryptRef.Update(ctx, metadataUpdatetoUpdate, rm.ETag)
		if err != nil {
			hclog.L().Error("Failed to update encrypt routine: %v errmessge=%s", err, err.Error())
		}
		hclog.L().Info("Encrypt Routine successfully updated!", "info", nil)
	}

	routineDecryptBody := fmt.Sprintf("AEAD.DECRYPT_STRING(KEYS.KEYSET_CHAIN(\"gcp-kms://%s\", b\"%s\"), ciphertext, aad)", options.kmsKeyName, escapedWrappedKeyset)
	if deterministic {
		routineDecryptBody = fmt.Sprintf("DETERMINISTIC_DECRYPT_BYTES(KEYS.KEYSET_CHAIN(\"gcp-kms://%s\", b\"%s\"), ciphertext, aad)", options.kmsKeyName, escapedWrappedKeyset)
	}

	routineDecryptRef := bigqueryClient.Dataset(options.datasetId).Routine(options.routineId + "decrypt")

	routineExists = true
	rm, err = routineDecryptRef.Metadata(ctx)
	if err != nil {
		routineExists = false
	}
	//	fmt.Printf("routineExists=%v", routineExists)

	if !routineExists {
		var metadataDecrypt *bigquery.RoutineMetadata
		if deterministic {
			metadataDecrypt = &bigquery.RoutineMetadata{
				Type:     "SCALAR_FUNCTION",
				Language: "SQL",
				Body:     routineDecryptBody,
				Arguments: []*bigquery.RoutineArgument{
					{Name: "ciphertext", DataType: &bigquery.StandardSQLDataType{TypeKind: "BYTES"}},
					{Name: "aad", DataType: &bigquery.StandardSQLDataType{TypeKind: "BYTES"}},
				},
			}
		} else {
			// non deterministic
			metadataDecrypt = &bigquery.RoutineMetadata{
				Type:     "SCALAR_FUNCTION",
				Language: "SQL",
				Body:     routineDecryptBody,
				Arguments: []*bigquery.RoutineArgument{
					{Name: "ciphertext", DataType: &bigquery.StandardSQLDataType{TypeKind: "BYTES"}},
					{Name: "aad", DataType: &bigquery.StandardSQLDataType{TypeKind: "STRING"}},
				},
			}
		}
		err = routineDecryptRef.Create(ctx, metadataDecrypt)
		if err != nil {
			hclog.L().Error("Failed to create decrypt routine: %v", err)
		}
		hclog.L().Info("Decrypt Routine successfully created!", "info", nil)
	} else {
		var metadataUpdatetoUpdate *bigquery.RoutineMetadataToUpdate
		if deterministic {
			metadataUpdatetoUpdate = &bigquery.RoutineMetadataToUpdate{
				Type:     "SCALAR_FUNCTION",
				Language: "SQL",
				Body:     routineDecryptBody,
				Arguments: []*bigquery.RoutineArgument{
					{Name: "ciphertext", DataType: &bigquery.StandardSQLDataType{TypeKind: "BYTES"}},
					{Name: "aad", DataType: &bigquery.StandardSQLDataType{TypeKind: "BYTES"}},
				},
			}
		} else {
			metadataUpdatetoUpdate = &bigquery.RoutineMetadataToUpdate{
				Type:     "SCALAR_FUNCTION",
				Language: "SQL",
				Body:     routineDecryptBody,
				Arguments: []*bigquery.RoutineArgument{
					{Name: "ciphertext", DataType: &bigquery.StandardSQLDataType{TypeKind: "BYTES"}},
					{Name: "aad", DataType: &bigquery.StandardSQLDataType{TypeKind: "STRING"}},
				},
			}
		}
		_, err = routineDecryptRef.Update(ctx, metadataUpdatetoUpdate, rm.ETag)
		if err != nil {
			hclog.L().Error("Failed to update decrypt routine: %v errmessge=%s", err, err.Error())
		}
		hclog.L().Info("Decrypt Routine successfully updated!", "info", nil)
	}
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
			if err != nil {
				hclog.L().Error("failed to update the status")
			}

			// save the keyhandle for the field
			saveKeyToConfig(newKh, fieldName, b, ctx, req, true)

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
			}

			// save the keyhandle for the field
			saveKeyToConfig(newKh, fieldName, b, ctx, req, true)

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
		}

		// save the keyhandle for the field
		saveKeyToConfig(newKh, fieldName, b, ctx, req, true)

		// extract the JSON from the new key
		buf := new(bytes.Buffer)
		jsonWriter := keyset.NewJSONWriter(buf)
		insecurecleartextkeyset.Write(newKh, jsonWriter)
		// unmarshall the keyset
		str := buf.String()
		resp[fieldName] = str

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
			}

			// save the keyhandle for the field
			saveKeyToConfig(newKh, fieldName, b, ctx, req, true)

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
	_, err := b.pathConfigWriteOverwriteCheck(ctx, req, data, true)
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
