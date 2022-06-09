package aeadplugin

import (
	"context"
	"encoding/json"
	"testing"

	lorem "github.com/bozaro/golorem"

	"github.com/hashicorp/vault/sdk/logical"
)

type Key struct {
	KeyData struct {
		TypeURL         string `json:"typeUrl"`
		Value           string `json:"value"`
		KeyMaterialType string `json:"keyMaterialType"`
	} `json:"keyData"`
	Status           string `json:"status"`
	KeyID            int    `json:"keyId"`
	OutputPrefixType string `json:"outputPrefixType"`
}
type encryptionJsonKeyStruct struct {
	PrimaryKeyID int   `json:"primaryKeyId"`
	Key          []Key `json:"key"`
}

func BenchmarkPathAeadEncrypt(benchmarkParent *testing.B) {

	benchmarkParent.Run("BenchEncrypt", func(benchmark *testing.B) {

		backend, storage := testBackend(benchmark)
		prepareData(benchmark, backend, storage)
		benchmark.ResetTimer()

		for i := 0; i < benchmark.N; i++ {

			updatedData := make(map[string]interface{})
			updatedData["random_field1"] = "plaintext"

			ctx := context.Background()

			benchmark.StartTimer() // start counting operations/per second

			_, errorRequest := backend.HandleRequest(ctx, &logical.Request{
				Storage:   storage,
				Operation: logical.UpdateOperation,
				Path:      "encrypt",
				Data:      updatedData,
			})
			benchmark.StopTimer()

			if errorRequest != nil {
				benchmark.Fatal(errorRequest)
			}
		}
	})

}

func BenchmarkPathAeadRandomString(benchmarkParent *testing.B) {

	benchmarkParent.Run("BenchEncrypt", func(benchmark *testing.B) {

		backend, storage := testBackend(benchmark)
		prepareData(benchmark, backend, storage)
		benchmark.ResetTimer()

		for i := 0; i < benchmark.N; i++ {

			updatedData := make(map[string]interface{})
			updatedData["random_field1"] = lorem.New().Word(9, 9)

			ctx := context.Background()

			benchmark.StartTimer() // start counting operations/per second

			_, errorRequest := backend.HandleRequest(ctx, &logical.Request{
				Storage:   storage,
				Operation: logical.UpdateOperation,
				Path:      "encrypt",
				Data:      updatedData,
			})
			benchmark.StopTimer()

			if errorRequest != nil {
				benchmark.Fatal(errorRequest)
			}
		}
	})

}

func BenchmarkPathAeadDecrypt(benchmarkParent *testing.B) {

	benchmarkParent.Run("BenchDecrypt", func(benchmark *testing.B) {

		backend, storage := testBackend(benchmark)
		prepareData(benchmark, backend, storage)
		benchmark.ResetTimer()

		for i := 0; i < benchmark.N; i++ {

			updatedData := make(map[string]interface{})
			updatedData["random_field1"] = "plaintext"
			updatedData["random_field2"] = "plaintext"

			ctx := context.Background()

			responseEncrypt, errorRequestEncrypt := backend.HandleRequest(ctx, &logical.Request{
				Storage:   storage,
				Operation: logical.UpdateOperation,
				Path:      "encrypt",
				Data:      updatedData,
			})

			if errorRequestEncrypt != nil {
				benchmark.Fatal("errorRequestEncrypt", errorRequestEncrypt)
			}

			benchmark.StartTimer() // start counting operations/per second

			_, errorRequestDecrypt := backend.HandleRequest(ctx, &logical.Request{
				Storage:   storage,
				Operation: logical.UpdateOperation,
				Path:      "decrypt",
				Data:      responseEncrypt.Data,
			})
			if errorRequestDecrypt != nil {
				benchmark.Fatal("errorRequestDecrypt", errorRequestDecrypt)
			}

			benchmark.StopTimer()

		}
	})

}
func prepareData(benchmark *testing.B, backend *backend, storage logical.Storage) {

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
		benchmark.Fatal("marshalingError", errorMarshaling)
	}

	encryptionMap := map[string]interface{}{
		"random_field1": string(encryptionJsonKey),
		"random_field2": string(encryptionJsonKey),
	}

	// store the config
	saveConfigforBenchmark(backend, storage, encryptionMap, benchmark)
}
func saveConfigforBenchmark(backend *backend, storage logical.Storage, data map[string]interface{}, benchmark *testing.B) {
	contextVar := context.Background()

	_, errorHandling := backend.HandleRequest(contextVar, &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      "configOverwrite",
		Data:      data,
	})
	if errorHandling != nil {
		benchmark.Fatal("saveConfigForBenchmark", errorHandling)
	}
}
