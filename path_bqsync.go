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
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func (b *backend) pathBQKeySync(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	for keyField, encryptionKey := range AEAD_CONFIG.Items() {
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
	projectId           string
	encryptDatasetId    string
	decryptDatasetId    string
	encryptRoutineId    string
	decryptRoutineId    string
	detRoutinePrefix    string
	nondetRoutinePrefix string
	kmsKeyName          string
	fieldName           string
}

func doBQSync(kh *keyset.Handle, fieldName string, deterministic bool) {

	var options Options
	resolveOptions(&options, fieldName, deterministic)

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

	bigqueryClient, err := bigquery.NewClient(ctx, options.projectId)
	if err != nil {
		hclog.L().Error("Failed to create a bigquery client:  %v", err)

	}
	defer bigqueryClient.Close()

	// 4. Create a BigQuery Routine. You'll likely want to create one Routine each for encryption/decryption.
	routineEncryptBody := fmt.Sprintf("AEAD.ENCRYPT(KEYS.KEYSET_CHAIN(\"gcp-kms://%s\", b\"%s\"), plaintext, aad)", options.kmsKeyName, escapedWrappedKeyset)
	if deterministic {
		routineEncryptBody = fmt.Sprintf("DETERMINISTIC_ENCRYPT(KEYS.KEYSET_CHAIN(\"gcp-kms://%s\", b\"%s\"), plaintext, aad)", options.kmsKeyName, escapedWrappedKeyset)
	}

	routineEncryptRef := bigqueryClient.Dataset(options.encryptDatasetId).Routine(options.encryptRoutineId)
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

	routineDecryptRef := bigqueryClient.Dataset(options.decryptDatasetId).Routine(options.decryptRoutineId)

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

func resolveOptions(options *Options, fieldName string, deterministic bool) {

	// set the defaults
	options.kmsKeyName = "projects/your-kms-project/locations/europe/keyRings/tink-keyring/cryptoKeys/key1" // Format: 'projects/.../locations/.../keyRings/.../cryptoKeys/...'
	options.projectId = "your-bq-project"
	options.encryptDatasetId = "pii_dataset_eu"
	options.decryptDatasetId = "pii_dataset_eu"
	options.detRoutinePrefix = "pii_daead_"
	options.nondetRoutinePrefix = "pii_aead_"

	// set any overrides
	kmsKeyInterface, ok := AEAD_CONFIG.Get("BQ_KMSKEY")
	if ok {
		options.kmsKeyName = fmt.Sprintf("%s", kmsKeyInterface)
	}
	projectIdInterface, ok := AEAD_CONFIG.Get("BQ_PROJECT")
	if ok {
		options.projectId = fmt.Sprintf("%s", projectIdInterface)
	}
	encryptDatasetIdInterface, ok := AEAD_CONFIG.Get("BQ_DEFAULT_ENCRYPT_DATASET")
	if ok {
		options.encryptDatasetId = fmt.Sprintf("%s", encryptDatasetIdInterface)
	}
	decryptDatasetIdInterface, ok := AEAD_CONFIG.Get("BQ_DEFAULT_DECRYPT_DATASET")
	if ok {
		options.decryptDatasetId = fmt.Sprintf("%s", decryptDatasetIdInterface)
	}
	detRoutinePrefixInterface, ok := AEAD_CONFIG.Get("BQ_ROUTINE_DET_PREFIX")
	if ok {
		options.detRoutinePrefix = fmt.Sprintf("%s", detRoutinePrefixInterface)
	}
	nondetRoutinePrefixInterface, ok := AEAD_CONFIG.Get("BQ_ROUTINE_NONDET_PREFIX")
	if ok {
		options.nondetRoutinePrefix = fmt.Sprintf("%s", nondetRoutinePrefixInterface)
	}

	// fieldName might have a "-" in it, but "-" are not allowed in BQ, so translate them to "_"
	options.fieldName = strings.Replace(fieldName, "-", "_", -1)
	if deterministic {
		options.encryptRoutineId = options.detRoutinePrefix + options.fieldName + "_encrypt"
		options.decryptRoutineId = options.detRoutinePrefix + options.fieldName + "_decrypt"
	} else {
		options.encryptRoutineId = options.nondetRoutinePrefix + options.fieldName + "_encrypt"
		options.decryptRoutineId = options.nondetRoutinePrefix + options.fieldName + "_decrypt"
	}

	// if we have a config entry for the encrypt or decrypt routine then use that as the dataset
	overrideBQDatasetInterface, ok := AEAD_CONFIG.Get(options.encryptRoutineId)
	if ok {
		options.encryptDatasetId = fmt.Sprintf("%s", overrideBQDatasetInterface)
	}
	overrideBQDatasetInterface, ok = AEAD_CONFIG.Get(options.decryptRoutineId)
	if ok {
		options.decryptDatasetId = fmt.Sprintf("%s", overrideBQDatasetInterface)
	}
}
