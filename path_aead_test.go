package aeadplugin

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestPathAeadEncrypt(test *testing.T) {

	backend, storage := testBackend(test)
	prepareTestData(test, backend, storage)
	updatedData := make(map[string]interface{})
	updatedData["random_field1"] = "plaintext"
	contextVar := context.Background()

	response, errorRequest := backend.HandleRequest(contextVar, &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "encrypt",
		Data:      updatedData,
	})

	if errorRequest != nil {
		test.Fatal(errorRequest)
	}
	expectedMockObject := map[string]interface{}{
		"random_field1": "AQKE8bGXsDZ5DHjLdThQAB96z0YgmUN1F6jWCYNO",
	}
	assert.EqualValues(test, expectedMockObject, response.Data)
}

func TestPathAeadDecrypt(test *testing.T) {

	backend, storage := testBackend(test)
	prepareTestData(test, backend, storage)
	updatedData := make(map[string]interface{})
	updatedData["random_field1"] = "AQKE8bGXsDZ5DHjLdThQAB96z0YgmUN1F6jWCYNO"
	contextVar := context.Background()

	response, errorRequest := backend.HandleRequest(contextVar, &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "decrypt",
		Data:      updatedData,
	})

	if errorRequest != nil {
		test.Fatal(errorRequest)
	}
	expectedMockObject := map[string]interface{}{
		"random_field1": "plaintext",
	}
	assert.EqualValues(test, expectedMockObject, response.Data)

}

func prepareTestData(test *testing.T, backend *backend, storage logical.Storage) {

	encryptionKey := encryptionJsonKeyStruct{
		PrimaryKeyID: 42267057,
		Key: []Key{
			Key{
				KeyData: struct {
					TypeURL         string `json:"typeUrl"`
					Value           string `json:"value"`
					KeyMaterialType string `json:"keyMaterialType"`
				}{
					TypeURL:         "type.googleapis.com/google.crypto.tink.AesSivKey",
					Value:           "EkDAEgACCd1/yruZMuI49Eig5Glb5koi0DXgx1mXVALYJWNRn5wYuQR46ggNuMhFfhrJCsddVp/Q7Pot2hvHoaQS",
					KeyMaterialType: "SYMMETRIC",
				},
				Status:           "ENABLED",
				KeyID:            42267057,
				OutputPrefixType: "TINK",
			},
		},
	}

	encryptionJsonKey, errorMarshaling := json.Marshal(&encryptionKey)

	if errorMarshaling != nil {
		test.Fatal("marshalingError", errorMarshaling)
	}

	encryptionMap := map[string]interface{}{
		"random_field1": string(encryptionJsonKey),
		"random_field2": string(encryptionJsonKey),
	}

	// store the config
	saveConfig(backend, storage, encryptionMap, true, test)
}
