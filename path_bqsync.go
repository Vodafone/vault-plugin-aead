package aeadplugin

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/bigquery"
	kms "cloud.google.com/go/kms/apiv1"
	"github.com/Vodafone/vault-plugin-aead/aeadutils"
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
		}

		encryptionKeyStr, deterministic := aeadutils.IsKeyJsonDeterministic(encryptionKey)
		if deterministic {
			kh, _, err := aeadutils.CreateInsecureHandleAndDeterministicAead(encryptionKeyStr)
			if err != nil {
				hclog.L().Error("failed to create deterministic key handle")
				return &logical.Response{
					Data: make(map[string]interface{}),
				}, err
			}
			doBQSync(kh, fieldName, true)
			// do deterministic sync
		} else {
			kh, _, err := aeadutils.CreateInsecureHandleAndAead(encryptionKeyStr)
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

	// fieldName might have a "-" in it, but "-" are not allowed in BQ, so translate them to "_"
	fieldName = strings.Replace(fieldName, "-", "_", -1)
	fieldName = aeadutils.RemoveKeyPrefix(fieldName)

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

	// if <region> is not there, we can call the create routine
	// if <region> is there we need to check what is present for <region> EU, europe_west1, europe_west2, europe_west3 and reset name of the dataset and the KMS key to the kms of that region
	// projects/vf-cis-rubik-tst-kms/locations/<region>/keyRings/hsm-key-tink-pf1-<region>/cryptoKeys/bq-key
	// projects/vf-cis-rubik-tst-kms/locations/europe/keyRings/hsm-key-tink-pf1-europe/cryptoKeys/bq-key
	// TODO
	bigqueryClient, err := bigquery.NewClient(ctx, options.projectId)
	if err != nil {
		hclog.L().Error("failed to setup bigqueryclient:  %v", err)
		return
	}
	defer bigqueryClient.Close()

	// loop through possible permeatations
	regionlist := [5]string{"unspecified", "eu", "europe_west1", "europe_west2", "europe_west3"} // note that these map to expected dataset names so EU is lower case and europe-west1 has underscore instead of dash
	for _, region := range regionlist {

		newOptions := Options(options)
		// options.encryptDatasetId = "vfpf1_dh_lake_aead_encrypt_<region>_lv_s"
		// options.decryptDatasetId = "vfpf1_dh_lake_<category>_aead_decrypt_<region>_lv_s"

		// first a simple substitution for <category>
		if strings.Contains(options.encryptDatasetId, "_<category>") {
			newOptions.encryptDatasetId = strings.Replace(options.encryptDatasetId, "<category>", fieldName, -1)
		}
		if strings.Contains(options.decryptDatasetId, "_<category>") {
			newOptions.decryptDatasetId = strings.Replace(options.decryptDatasetId, "<category>", fieldName, -1)
		}

		// search for the ENCRYPT dataset
		if region == "unspecified" {
			newOptions.encryptDatasetId = strings.Replace(newOptions.encryptDatasetId, "_<region>", "", -1)
		} else {
			newOptions.encryptDatasetId = strings.Replace(newOptions.encryptDatasetId, "<region>", region, -1)
		}
		md, err := bigqueryClient.Dataset(newOptions.encryptDatasetId).Metadata(ctx)
		if err == nil {
			actualDatasetRegion := strings.ToLower(md.Location)

			// infer the kms name
			// kms has the form:
			// projects/vf-cis-rubik-tst-kms/locations/<region>/keyRings/hsm-key-tink-pf1-<region>/cryptoKeys/bq-key
			// and needs to be translated into
			// projects/vf-cis-rubik-tst-kms/locations/europe/keyRings/hsm-key-tink-pf1-europe/cryptoKeys/bq-key
			// or
			// projects/vf-cis-rubik-tst-kms/locations/europe-west1/keyRings/hsm-key-tink-pf1-europe-west1/cryptoKeys/bq-key

			expectedKMSRegion := actualDatasetRegion
			if actualDatasetRegion == "eu" {
				expectedKMSRegion = "europe"
			}
			newOptions.kmsKeyName = strings.Replace(newOptions.kmsKeyName, "<region>", expectedKMSRegion, -1)

			// // does the kms exist
			req := &kmspb.GetCryptoKeyRequest{
				Name: newOptions.kmsKeyName,
			}
			_, err := kmsClient.GetCryptoKey(ctx, req)

			if err == nil {
				// now we have a valid dataset and a valid kms (this doesn't mean we have access though)
				// 2. Wrap the binary keyset with KMS.

				encryptReq := &kmspb.EncryptRequest{
					Name:      newOptions.kmsKeyName,
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

				doBQRoutineCreateOrUpdate(ctx, newOptions, escapedWrappedKeyset, deterministic, "encrypt")
			}
		}

		// search for the DECRYPT dataset
		if region == "unspecified" {
			newOptions.decryptDatasetId = strings.Replace(newOptions.decryptDatasetId, "_<region>", "", -1)
		} else {
			newOptions.decryptDatasetId = strings.Replace(newOptions.decryptDatasetId, "<region>", region, -1)
		}
		md, err = bigqueryClient.Dataset(newOptions.decryptDatasetId).Metadata(ctx)
		if err == nil {
			actualDatasetRegion := strings.ToLower(md.Location)

			// infer the kms name
			// kms has the form:
			// projects/vf-cis-rubik-tst-kms/locations/<region>/keyRings/hsm-key-tink-pf1-<region>/cryptoKeys/bq-key
			// and needs to be translated into
			// projects/vf-cis-rubik-tst-kms/locations/europe/keyRings/hsm-key-tink-pf1-europe/cryptoKeys/bq-key
			// or
			// projects/vf-cis-rubik-tst-kms/locations/europe-west1/keyRings/hsm-key-tink-pf1-europe-west1/cryptoKeys/bq-key

			expectedKMSRegion := actualDatasetRegion
			if actualDatasetRegion == "eu" {
				expectedKMSRegion = "europe"
			}
			newOptions.kmsKeyName = strings.Replace(newOptions.kmsKeyName, "<region>", expectedKMSRegion, -1)

			// // does the kms exist
			req := &kmspb.GetCryptoKeyRequest{
				Name: newOptions.kmsKeyName,
			}
			_, err := kmsClient.GetCryptoKey(ctx, req)

			if err == nil {
				// now we have a valid dataset and a valid kms (this doesn't mean we have access though)
				// 2. Wrap the binary keyset with KMS.

				encryptReq := &kmspb.EncryptRequest{
					Name:      newOptions.kmsKeyName,
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

				doBQRoutineCreateOrUpdate(ctx, newOptions, escapedWrappedKeyset, deterministic, "decrypt")
			}
		}

	}

}

func doBQRoutineCreateOrUpdate(ctx context.Context, options Options, escapedWrappedKeyset string, deterministic bool, routineType string) {

	bigqueryClient, err := bigquery.NewClient(ctx, options.projectId)
	if err != nil {
		hclog.L().Error("Failed to create a bigquery client:  %v", err)

	}
	defer bigqueryClient.Close()

	if routineType == "encrypt" {
		// 4. Create a BigQuery Routine. You'll likely want to create one Routine each for encryption/decryption.
		routineEncryptBody := fmt.Sprintf("AEAD.ENCRYPT(KEYS.KEYSET_CHAIN(\"gcp-kms://%s\", b\"%s\"), plaintext, aad)", options.kmsKeyName, escapedWrappedKeyset)
		if deterministic {
			routineEncryptBody = fmt.Sprintf("DETERMINISTIC_ENCRYPT(KEYS.KEYSET_CHAIN(\"gcp-kms://%s\", b\"%s\"), plaintext, aad)", options.kmsKeyName, escapedWrappedKeyset)
		}

		routineEncryptRef := bigqueryClient.Dataset(options.encryptDatasetId).Routine(options.encryptRoutineId)
		routineExists := true
		var rm *bigquery.RoutineMetadata
		rm, err = routineEncryptRef.Metadata(ctx)
		if err != nil {
			// try again - api's seem a bit flakey
			time.Sleep(1 * time.Second)
			routineEncryptRef := bigqueryClient.Dataset(options.encryptDatasetId).Routine(options.encryptRoutineId)
			rm, err = routineEncryptRef.Metadata(ctx)
			if err != nil {
				routineExists = false
			}
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
				hclog.L().Error("Failed to create encrypt routine: " + options.encryptDatasetId + ":" + options.encryptRoutineId + " Error:" + err.Error())
			} else {
				hclog.L().Info("Encrypt Routine successfully created! " + options.encryptDatasetId + ":" + options.encryptRoutineId)
			}
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
				hclog.L().Error("Failed to update encrypt routine: " + options.encryptDatasetId + ":" + options.encryptRoutineId + " Error:" + err.Error())
			} else {
				hclog.L().Info("Encrypt Routine successfully updated! " + options.encryptDatasetId + ":" + options.encryptRoutineId)
			}
		}
	} else {
		// we are doing a decrypt routine
		routineDecryptBody := fmt.Sprintf("AEAD.DECRYPT_STRING(KEYS.KEYSET_CHAIN(\"gcp-kms://%s\", b\"%s\"), ciphertext, aad)", options.kmsKeyName, escapedWrappedKeyset)
		if deterministic {
			//routineDecryptBody = fmt.Sprintf("DETERMINISTIC_DECRYPT_BYTES(KEYS.KEYSET_CHAIN(\"gcp-kms://%s\", b\"%s\"), ciphertext, aad)", options.kmsKeyName, escapedWrappedKeyset)
			routineDecryptBody = fmt.Sprintf("DETERMINISTIC_DECRYPT_STRING(KEYS.KEYSET_CHAIN(\"gcp-kms://%s\", b\"%s\"), ciphertext, aad)", options.kmsKeyName, escapedWrappedKeyset)
		}

		routineDecryptRef := bigqueryClient.Dataset(options.decryptDatasetId).Routine(options.decryptRoutineId)

		routineExists := true
		rm, err := routineDecryptRef.Metadata(ctx)
		if err != nil {
			routineExists = false
		}
		//	fmt.Printf("routineExists=%v", routineExists)

		if !routineExists {
			// routine DOES exist
			var metadataDecrypt *bigquery.RoutineMetadata
			if deterministic {
				// deterministic
				metadataDecrypt = &bigquery.RoutineMetadata{
					Type:     "SCALAR_FUNCTION",
					Language: "SQL",
					Body:     routineDecryptBody,
					Arguments: []*bigquery.RoutineArgument{
						{Name: "ciphertext", DataType: &bigquery.StandardSQLDataType{TypeKind: "BYTES"}},
						{Name: "aad", DataType: &bigquery.StandardSQLDataType{TypeKind: "STRING"}},
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
				hclog.L().Error("Failed to create decrypt routine: " + options.decryptDatasetId + ":" + options.decryptRoutineId + " Error:" + err.Error())
			} else {
				hclog.L().Info("Decrypt Routine successfully created! " + options.decryptDatasetId + ":" + options.decryptRoutineId)
			}
		} else {
			// routine DOES NOT exist
			var metadataUpdatetoUpdate *bigquery.RoutineMetadataToUpdate
			if deterministic {
				metadataUpdatetoUpdate = &bigquery.RoutineMetadataToUpdate{
					Type:     "SCALAR_FUNCTION",
					Language: "SQL",
					Body:     routineDecryptBody,
					Arguments: []*bigquery.RoutineArgument{
						{Name: "ciphertext", DataType: &bigquery.StandardSQLDataType{TypeKind: "BYTES"}},
						{Name: "aad", DataType: &bigquery.StandardSQLDataType{TypeKind: "STRING"}},
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
				hclog.L().Error("Failed to update decrypt routine: " + options.decryptDatasetId + ":" + options.decryptRoutineId + " Error:" + err.Error())
			} else {
				hclog.L().Info("Decrypt Routine successfully updated! " + options.decryptDatasetId + ":" + options.decryptRoutineId)
			}
		}
	}
}

func resolveOptions(options *Options, fieldName string, deterministic bool) {

	// set the defaults
	options.kmsKeyName = "projects/your-kms-project/locations/<region>/keyRings/hsm-key-tink-<lm>-<region>/cryptoKeys/bq-key" // Format: 'projects/.../locations/.../keyRings/.../cryptoKeys/...'
	options.projectId = "your-bq-project"
	options.encryptDatasetId = "vf<lm>_dh_lake_aead_encrypt_<region>_lv_s"
	options.decryptDatasetId = "vf<lm>_dh_lake_<category>_aead_decrypt_<region>_lv_s"
	options.detRoutinePrefix = "siv"
	options.nondetRoutinePrefix = "gcm"

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
		options.encryptRoutineId = options.fieldName + "_" + options.detRoutinePrefix + "_encrypt" // ie routine name = address_siv_encrypt
		options.decryptRoutineId = options.fieldName + "_" + options.detRoutinePrefix + "_decrypt" // ie routine name = address_siv_decrypt
	} else {
		options.encryptRoutineId = options.fieldName + "_" + options.nondetRoutinePrefix + "_encrypt" // ie routine name = address_gcm_encrypt
		options.decryptRoutineId = options.fieldName + "_" + options.nondetRoutinePrefix + "_decrypt" // ie routine name = address_gcm_encrypt
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
