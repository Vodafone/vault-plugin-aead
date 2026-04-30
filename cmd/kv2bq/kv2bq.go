package main

import (
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"cloud.google.com/go/bigquery"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/daead"
	"gopkg.in/yaml.v2"

	aeadutils "github.com/Vodafone/vault-plugin-aead/aeadutils"
	"github.com/Vodafone/vault-plugin-aead/bqutils"
	kvutils "github.com/Vodafone/vault-plugin-aead/kvutils"

	cmap "github.com/orcaman/concurrent-map"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

func main() {

	var c conf

	c.getConf()

	fmt.Printf("\nc.DryRun=%v", c.DryRun)

	// log.Fatal("\nDryRun exiting")

	var envMap = cmap.New()
	envMap.Set("BQ_KMSKEY", c.KmsKeyName)
	envMap.Set("BQ_PROJECT", c.ProjectId)
	envMap.Set("BQ_DEFAULT_ENCRYPT_DATASET", c.EncryptDatasetId)
	envMap.Set("BQ_DEFAULT_DECRYPT_DATASET", c.DecryptDatasetId)
	envMap.Set("BQ_ROUTINE_DET_PREFIX", c.DetRoutinePrefix)
	envMap.Set("BQ_ROUTINE_NONDET_PREFIX", c.NondetRoutinePrefix)

	readKV(c, envMap)

}

type conf struct {
	VaultUrl            string   `yaml:"vaultUrl"`
	ApproleId           string   `yaml:"approleId"`
	SecretId            string   `yaml:"secretId"`
	Engine              string   `yaml:"engine"`
	EngineVersion       string   `yaml:"engineVersion"`
	ProjectId           string   `yaml:"projectId"`
	EncryptDatasetId    string   `yaml:"encryptDatasetId"`
	DecryptDatasetId    string   `yaml:"decryptDatasetId"`
	DetRoutinePrefix    string   `yaml:"detRoutinePrefix"`
	NondetRoutinePrefix string   `yaml:"nondetRoutinePrefix"`
	KmsKeyName          string   `yaml:"kmsKeyName"`
	KvKeys              []string `yaml:"kvKeys"`
	DryRun              bool     `yaml:"dryRun"`
}

func (c *conf) getConf() *conf {

	yamlFile, err := os.ReadFile("./conf.yaml")
	if err != nil {
		log.Printf("\nyamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	return c
}

func readKV(vaultconf conf, bqconfig cmap.ConcurrentMap) {
	ctx := context.Background()

	// get a client
	client, err := kvutils.KvGetClient(vaultconf.VaultUrl, "", vaultconf.ApproleId, vaultconf.SecretId)

	if err != nil {
		fmt.Print("\nfailed to initialize Vault client1")
		return
	}

	var paths []string
	if len(vaultconf.KvKeys) > 0 {
		paths = vaultconf.KvKeys
	} else {
		// read the paths recursively
		paths, err = kvutils.KvGetSecretPaths(client, vaultconf.Engine, vaultconf.EngineVersion, "")
	}
	fmt.Printf("\npaths=%v", paths)

	if err != nil || paths == nil {
		fmt.Print("failed to read paths")
	}

	var datasets map[string]*bigquery.Dataset
	if !vaultconf.DryRun {
		datasets, err = bqutils.GetBQDatasets(ctx, vaultconf.ProjectId)
		if err != nil {
			fmt.Println("Failed to list Datasets")
			return
		}
		fmt.Printf("datasets=%v\n", datasets)
	}
	
	var wg sync.WaitGroup
	var keyIdSlice []int
	var keyValueSlice []string

	// iterate through the paths
	for _, path := range paths {
		keyFound := false
		kvsecret, err := kvutils.KvGetSecret(client, vaultconf.Engine, vaultconf.EngineVersion, path)
		if err != nil || kvsecret.Data == nil {
			fmt.Print("\nfailed to read the secrets in folder " + path)
			continue
		}

		if strings.HasPrefix(path, "gcm/") || strings.HasPrefix(path, "siv/") {

			keyFound = true
			jsonKey, ok := kvsecret.Data["data"]

			if !ok {
				fmt.Printf("\nfailed to read back the aead engine %s key %s", vaultconf.Engine, path)
			}
			fmt.Printf("\njSonKey=%s", jsonKey)

			if _, kh, err := aeadutils.IsSecretAnAEADKeyset(jsonKey, path); err != nil {
				fmt.Printf("\nfailed to read valid aead key %s/%s", vaultconf.Engine, path)
			} else {
				fmt.Printf("\n%s/%s is a valid aead key", vaultconf.Engine, path)
				_, keyIdSlice, keyValueSlice, _ = checkIfKeyIdIsDupe(jsonKey, path, keyIdSlice, keyValueSlice)

				newkeyname := aeadutils.RemoveKeyPrefix(path)
				deterministic := aeadutils.IsKeyHandleDeterministic(kh)
				// _, deterministic := aeadutils.IsKeyJsonDeterministic(jsonKey)

				if deterministic {

					tinkDetAead, err := daead.New(kh)
					if err != nil {
						fmt.Printf("\nfailed to create deterministic aead err=%v", err)
						continue
					}

					// encrypt it
					ct, err := tinkDetAead.EncryptDeterministically([]byte("Hello World"), []byte("additionalData"))
					if err != nil {
						fmt.Printf("\nfailed to encrypt deterministic err=%v", err)
						continue
					}
					b64str := b64.StdEncoding.EncodeToString(ct)

					fmt.Printf("\n Encrypted value for :  <Hello World> is %s", b64str)

				} else {
					tinkAead, err := aead.New(kh)
					if err != nil {
						fmt.Printf("\nfailed to create non deterministic aead err=%v", err)
						continue
					}

					// encrypt it
					ct, err := tinkAead.Encrypt([]byte("Hello World"), []byte("additionalData"))
					if err != nil {
						fmt.Printf("\nfailed to encrypt deterministic err=%v", err)
						continue
					}
					b64str := b64.StdEncoding.EncodeToString(ct)

					fmt.Printf("\n Encrypted value for :  <Hello World> is %s", b64str)
				}
				if !vaultconf.DryRun {
					fmt.Printf("\n DryRun=%v Doing BQSYnc", vaultconf.DryRun)
					wg.Add(1)
					go func() {
						defer wg.Done()
						bqutils.DoBQSync(ctx, kh, newkeyname, deterministic, bqconfig, datasets)
					}()
				} else {
					fmt.Printf("\n DryRun=%v Skipping BQSYnc", vaultconf.DryRun)
				}
			}
		}

		if !keyFound {
			fmt.Print("\nfailed to read back any keys in KV secret " + path)
		}

	}
	wg.Wait()
	return
}

func checkIfKeyIdIsDupe(secret interface{}, fName string, keyIdSlice []int, keyValueSlice []string) (int, []int, []string, error) {
	secretStr := fmt.Sprintf("%v", secret)
	fieldName := aeadutils.RemoveKeyPrefix(fName)
	var jMap map[string]aeadutils.KeySetStruct
	if err := json.Unmarshal([]byte(secretStr), &jMap); err != nil {
		fmt.Printf("\nfailed to unmarshall the secret %s", fName)
		return 0, keyIdSlice, keyValueSlice, err
	}

	keysetAsStruct := jMap[fieldName]

	if containsInt(keyIdSlice, keysetAsStruct.PrimaryKeyID) {
		fmt.Printf("\nDUPLICATE KeyId %v found for Key %s", keysetAsStruct.PrimaryKeyID, fName)
	} else {
		keyIdSlice = append(keyIdSlice, keysetAsStruct.PrimaryKeyID)
	}

	for _, v := range keysetAsStruct.Key {
		kd := v.KeyData
		if containsStr(keyValueSlice, kd.Value) {
			fmt.Printf("\nDUPLICATE KeyValue %v found for Key %s", kd.Value, fName)
		} else {
			keyValueSlice = append(keyValueSlice, kd.Value)
		}
	}

	return keysetAsStruct.PrimaryKeyID, keyIdSlice, keyValueSlice, nil
}

// create a function to return true if an int value is in an int slice
func containsInt(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// create a function to return true if a string value is in a string slice
func containsStr(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
