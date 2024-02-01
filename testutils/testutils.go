package testutils

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	kv "github.com/hashicorp/vault-plugin-secrets-kv"
	vault_api "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/logical/transit"
	vault_http "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
)

func SetupVault(t *testing.T) *vault_api.Client {
	cluster, vaultConfig := CreateVaultTestCluster(t)
	_ = vaultConfig
	defer cluster.Cleanup()
	client := cluster.Cores[0].Client
	return client
}

// in memory vault for testing
func CreateVaultTestCluster(t *testing.T) (*vault.TestCluster, map[string]string) {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current directory: %v", err)
	}
	pluginPath := filepath.Join(wd, "..", "vault", "plugins")
	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"kv":      kv.Factory,
			"transit": transit.Factory,
		},
		PluginDirectory: pluginPath,
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vault_http.Handler,
	})
	cluster.Start()
	cluster.Cores[0].Client.Sys().Unmount("secret")
	// Create KV V2 mount
	if err := cluster.Cores[0].Client.Sys().Mount("secret", &vault_api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
	}); err != nil {
		t.Fatal(err)
	}

	// ---
	client := cluster.Cores[0].Client

	// configureFf1(client, t, pluginPath)
	roleID, secretID := ConfigureApprole(client, t)
	return cluster, map[string]string{"VAULT_KV_APPROLE_ID": roleID, "VAULT_KV_SECRET_ID": secretID, "VAULT_KV_URL": client.Address()}
}

const vault_kv_url string = "https://zzz.vodafone.com"
const vault_kv_active string = "false"
const vault_kv_approle_id string = "xxxxxx"
const vault_kv_secret_id string = "yyyyyy"
const vault_kv_engine string = "secret"
const vault_kv_version string = "v2"
const vault_kv_writer_role = "kv-writer-role"
const vault_secretgenerator_iam_role = "secretgenerator-iam-role"

const vault_transit_active string = "false"
const vault_transit_url string = "http://localhost:8200"
const vault_transit_kv_approle_id string = "xxxxxx"
const vault_transit_kv_secret_id string = "yyyyyy"
const vault_transit_kv_engine string = "secret"
const vault_transit_kv_version string = "v2"
const vault_transit_namespace string = ""
const vault_transit_engine string = "transit"
const vault_transit_kek string = "my-key"

const bq_active string = "false"

const DeterministicKeyset = `{"primaryKeyId":97978150,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkALk9CVIh1NDBjiE+gBvL/+aJuCdFRZQBzQSp5DcVy/4DkhrGF7BKdt0xLxjyX4jIKN2Vki1rSza+ETgGPV4zLD","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1481824018,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkCXhcXHvfUMj8DWgWjfnxyWFz3GcOw8G1xB2PTcfPdbl93idxHTcmANzYLYW3KmsU0putTRfi3vxySALhSHaHl0","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3647454112,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkDeUHhnPioOIETPIbKfEcifAjnhxaeUJbRwT/TB6AurJG/qmhsbpGaHKFdhDHn6VtJ7I/tMWX7gFZTr1Db9f/3v","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":4039363563,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkAqIqBlB7q0W/bhp9RtivX770+nAYkEWxBkYjfPzbWiBWJZbM7YypfHbkOyyWPtkBc0yVK0YTUmqbWD0JpEJ63u","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3167099089,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkDfF2JLaeZPvRwMncPw8ZKhsoGDMvFDriu7RtdF1pgHvRefGKbAa56pU7IFQCzA+UWy+dBNtsLW2H5rbHsxM2FC","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":2568362933,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkC9CVw73BjO+OSjo3SFvUV7SUszpJnuKGnLWMbmD7cO3WFCIy2unxoyNPCHFDlzle1zU35vTZtoecnlsWScQUVl","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":97978150,"outputPrefixType":"TINK"}]}`
const NonDeterministicKeyset = `{"primaryKeyId":3192631270,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiBf14hIKBzJYUGjc4LXzaG3dT3aVsvv0vpyZJVZNh02MQ==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":2832419897,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiCW0m5ElDr8RznAl4ef3bXqgHgu9PL/js7K6NAZIjkDJw==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":2233686170,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiChGSKGi7odjL3mdwhQ03X5SGiVXTarRSKPZUn+xCUYyQ==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1532149397,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"GiApAwR1VAPVxpIrRiBGw2RziWx04nzHVDYu1ocipSDCvQ==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":3192631270,"outputPrefixType":"TINK"}]}`
const DeterministicSingleKey = `{"primaryKeyId":1481824018,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesSivKey","value":"EkALk9CVIh1NDBjiE+gBvL/+aJuCdFRZQBzQSp5DcVy/4DkhrGF7BKdt0xLxjyX4jIKN2Vki1rSza+ETgGPV4zLD","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":1481824018,"outputPrefixType":"TINK"}]}`

func GetVaultConfig(baseVaultConfig map[string]string) map[string]interface{} {
	configMap := map[string]interface{}{
		"VAULT_KV_ACTIVE":                   vault_kv_active,
		"VAULT_KV_URL":                      vault_kv_active,
		"VAULT_KV_ENGINE":                   vault_kv_engine,
		"VAULT_KV_VERSION":                  vault_kv_version,
		"VAULT_KV_APPROLE_ID":               vault_kv_approle_id,
		"VAULT_KV_SECRET_ID":                vault_kv_secret_id,
		"VAULT_TRANSIT_ACTIVE":              vault_transit_active,
		"VAULT_TRANSIT_URL":                 vault_transit_url,
		"VAULT_TRANSIT_APPROLE_ID":          vault_transit_kv_approle_id,
		"VAULT_TRANSIT_SECRET_ID":           vault_transit_kv_secret_id,
		"VAULT_TRANSIT_KV_ENGINE":           vault_transit_kv_engine,
		"VAULT_TRANSIT_KV_VERSION":          vault_transit_kv_version,
		"VAULT_TRANSIT_NAMESPACE":           vault_transit_namespace,
		"VAULT_TRANSIT_ENGINE":              vault_transit_engine,
		"VAULT_TRANSIT_KEK":                 vault_transit_kek,
		"VAULT_KV_WRITER_ROLE":              vault_kv_writer_role,
		"VAULT_KV_SECRETGENERATOR_IAM_ROLE": vault_secretgenerator_iam_role,
	}
	for k, v := range baseVaultConfig {
		configMap[k] = v
	}
	return configMap
}

func ConfigureApprole(client *vault_api.Client, t *testing.T) (string, string) {
	err := client.Sys().EnableAuth("approle", "approle", "")
	if err != nil {
		t.Fatal(err)
	}

	data := map[string]interface{}{
		"token_ttl":     "1h",
		"token_max_ttl": "4h",
	}

	_, err = client.Logical().Write("auth/approle/role/my-role", data)
	if err != nil {
		t.Fatal(err)
	}

	secretValues, err := client.Logical().Read("auth/approle/role/my-role/role-id")
	if err != nil {
		t.Fatal(err)
	}
	roleID := secretValues.Data["role_id"].(string)
	t.Log(roleID)

	secretValues, err = client.Logical().Write("auth/approle/role/my-role/secret-id", nil)
	if err != nil {
		t.Fatal(err)
	}
	secretID := secretValues.Data["secret_id"].(string)
	t.Log(secretID)
	return roleID, secretID
}

func configureFf1(client *vault_api.Client, t *testing.T, pluginPath string) {
	if err := client.Sys().Mount("transit", &vault_api.MountInput{
		Type: "transit",
	}); err != nil {
		t.Fatal(err)
	}
	pluginBin := filepath.Join(pluginPath, "vault-plugin-secrets-ff1")
	err := client.Sys().RegisterPlugin(&vault_api.RegisterPluginInput{
		Name:    "vault-plugin-secrets-ff1",
		Command: "vault-plugin-secrets-ff1",
		SHA256:  getSha256(pluginBin),
	})
	if err != nil {
		log.Fatal(err)
	}

	mountInput := &vault_api.MountInput{
		Type:        "vault-plugin-secrets-ff1",
		Description: "ff1 secrets",
	}

	if err := client.Sys().Mount("ff1-secrets/ff1", mountInput); err != nil {
		t.Fatal(err)
	}
}

func getSha256(fileName string) string {
	file, err := os.Open(fileName)
	if err != nil {
		return ""
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}

	hashValue := hash.Sum(nil)
	hashString := fmt.Sprintf("%x", hashValue)

	return hashString
}
