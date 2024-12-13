package kvutils

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"

	"github.com/Vodafone/vault-plugin-aead/aeadutils"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-retryablehttp"
	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
	authgcp "github.com/hashicorp/vault/api/auth/gcp"
	cmap "github.com/orcaman/concurrent-map"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

type KVOptions struct {
	Vault_kv_url               string
	Vault_kv_active            string
	Vault_kv_approle_id        string
	Vault_kv_secret_id         string
	Vault_kv_engine            string
	Vault_kv_version           string
	Vault_transit_active       string
	Vault_transit_url          string
	Vault_transit_approle_id   string
	Vault_transit_secret_id    string
	Vault_transit_kv_engine    string
	Vault_transit_kv_version   string
	Vault_transit_kv_push_path string
	Vault_transit_kv_pull_path string
	Vault_transit_namespace    string
	Vault_transit_engine       string
	// Vault_transit_tokenname        string
	Vault_transit_kek              string
	Vault_kv_writer_role           string
	Vault_secretgenerator_iam_role string
}

type KVConnection struct {
	Client         *vault.Client
	Engine         string
	Version        string `default:"v1"`
	Url            string
	Approle_id     string
	Secret_id      string
	Namespace      string
	Path           string `default:""`
	Kek            string
	Transit_engine string
}

func getGeneratedVaultSecretId(vault_addr string, vault_writer_secret_id string, vault_kv_writer_role string, vault_secretgenerator_iam_role string) (string, error) {

	if vault_writer_secret_id != "" {
		// we already have the secret id, no need to generate one
		return vault_writer_secret_id, nil
	}
	// 1. Get the SA we are working as
	saEmail, projectId, err := getMetadataInfo()
	if err != nil {
		fmt.Printf("oops error from getMetadataInfo=%s", err.Error())
		saEmail = "restricted-zone-restricted@vf-grp-neuronenabler-nonlive.iam.gserviceaccount.com"
		projectId = "vf-grp-neuronenabler-nonlive"
	}
	fmt.Printf("\nsaEmail=%s ProjectId=%s\n", saEmail, projectId)
	// saEmail = "gke-service-account@vf-grp-clouddmz-lab.iam.gserviceaccount.com"
	// fmt.Printf("\nsaEmail=%s ProjectId=%s\n", saEmail, projectId)

	// 2. use the SA and IAM role to generate a token for vault
	_, token, err := getVaultTokenGCPAuthIAM(saEmail, vault_addr, vault_secretgenerator_iam_role)
	if err != nil {
		fmt.Printf("oops error from getVaultTokenGCPAuthIAM=%s", err.Error())
		return "", err
	}
	fmt.Printf("\ntoken from getVaultTokenGCPAuthIAM=%s\n", token)

	// 3. use the token (scoped to only be able to generate a secret for an app role, to create a new secretid)
	newSecretId, err := createSecretIdForRole(vault_addr, token, vault_kv_writer_role)
	if err != nil {
		fmt.Printf("oops error from createSecretIdForRole=%s", err.Error())
		return "", err
	}
	fmt.Printf("\nnewSecretId from createSecretIdForRole=%s\n", newSecretId)
	return newSecretId, nil
}

// Fetches a key-value secret (kv-v2) after authenticating via AppRole.
func KvGetClientWithApprole(vault_addr string, namespace string, vault_writer_approle_id string, vault_writer_secret_id string, vault_writer_approle_name string, vault_secretgenerator_iam_role_name string) (*vault.Client, error) {

	generated_secret_id, err := getGeneratedVaultSecretId(vault_addr, vault_writer_secret_id, vault_writer_approle_name, vault_secretgenerator_iam_role_name)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate a secret id")
	} else {
		vault_writer_secret_id = generated_secret_id
	}
	return KvGetClient(vault_addr, namespace, vault_writer_approle_id, vault_writer_secret_id)
}
func KvGetClient(vault_addr string, namespace string, vault_approle_id string, vault_secret_id string) (*vault.Client, error) {

	os.Setenv("VAULT_ADDR", vault_addr)
	os.Setenv("APPROLE_ROLE_ID", vault_approle_id)
	os.Setenv("APPROLE_SECRET_ID", vault_secret_id)

	config := vault.DefaultConfig() // modify for more granular configuration

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Vault client: %w", err)
	}

	// A combination of a Role ID and Secret ID is required to log in to Vault
	// with an AppRole.
	// First, let's get the role ID given to us by our Vault administrator.

	// The Secret ID is a value that needs to be protected, so instead of the
	// app having knowledge of the secret ID directly, we have a trusted orchestrator (https://learn.hashicorp.com/tutorials/vault/secure-introduction?in=vault/app-integration#trusted-orchestrator)
	// give the app access to a short-lived response-wrapping token (https://www.vaultproject.io/docs/concepts/response-wrapping).
	// Read more at: https://learn.hashicorp.com/tutorials/vault/approle-best-practices?in=vault/auth-methods#secretid-delivery-best-practices
	// secretID := &auth.SecretID{FromFile: "path/to/wrapping-token"}
	// secretIDStr := os.Getenv("APPROLE_SECRET_ID")
	// fmt.Printf("\nVAULT_URL=%s", fmt.Sprintf("%v", vault_url))
	// fmt.Printf("\nAPPROLE_ROLE_ID=%s", roleID)
	// fmt.Printf("\nAPPROLE_SECRET_ID=%s", secretIDStr)
	// fmt.Printf("\nVAULT_TOKEN=%s", os.Getenv("VAULT_TOKEN"))
	secretID := &auth.SecretID{FromEnv: "APPROLE_SECRET_ID"}

	appRoleAuth, err := auth.NewAppRoleAuth(
		vault_approle_id,
		secretID,
		// auth.WithWrappingToken(), // Only required if the secret ID is response-wrapped.
	)
	if err != nil {
		return nil, fmt.Errorf("\nfailed to initialize AppRole auth method: %w", err)
	}

	var authInfo *vault.Secret
	if namespace == "" {
		authInfo, err = client.Auth().Login(context.Background(), appRoleAuth)
	} else {
		authInfo, err = client.WithNamespace(namespace).Auth().Login(context.Background(), appRoleAuth)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to login to AppRole auth method: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("no auth info was returned after login")
	}

	ti, err := authInfo.TokenID()

	client.SetToken(ti)

	return client, nil
}

// Fetches a key-value secret (kv-v2) after authenticating via AppRole.
func KvGetClientPwd(configUrlStr string, configPwdStr string, AEAD_CONFIG cmap.ConcurrentMap) (*vault.Client, error) {

	vault_url, ok := AEAD_CONFIG.Get(configUrlStr)
	if !ok {
		vault_url, ok = os.LookupEnv("VAULT_ADDR")
		if !ok {
			return nil, fmt.Errorf("%s not set in config and VAULT_ADDR env not set", configUrlStr)
		}
	} else {
		os.Setenv("VAULT_ADDR", fmt.Sprintf("%v", vault_url))
	}
	vault_pwd, ok := AEAD_CONFIG.Get(configPwdStr)
	if !ok {
		vault_pwd, ok = os.LookupEnv("VAULT_TOKEN")
		if !ok {
			return nil, fmt.Errorf("%s not set in config and VAULT_TOKEN env not set", configPwdStr)
		}
	} else {
		os.Setenv("VAULT_TOKEN", fmt.Sprintf("%v", vault_pwd))
	}

	config := vault.DefaultConfig() // modify for more granular configuration

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Vault client: %w", err)
	}

	client.SetToken(fmt.Sprintf("%v", vault_pwd))

	return client, nil
}

func KvPatchSecret(client *vault.Client, kv_engine string, kv_version string) (*vault.KVSecret, error) {
	// TODO
	dmp := make(map[string]interface{})
	dmp["foo"] = "bar"

	if kv_version == "v1" {
		return nil, client.KVv1(kv_engine).Put(context.Background(), "tmp", dmp)
	} else if kv_version == "v2" {
		return client.KVv2(kv_engine).Patch(context.Background(), "tmp", dmp)
	} else {
		return nil, fmt.Errorf("kv_version must be v1 or v2")
	}
}

func KvPutSecret(client *vault.Client, kv_engine string, kv_version string, secretPath string, secretMap map[string]interface{}) (*vault.KVSecret, error) {

	if kv_version == "v1" {
		return nil, client.KVv1(kv_engine).Put(context.Background(), secretPath, secretMap)
	} else if kv_version == "v2" {
		return client.KVv2(kv_engine).Put(context.Background(), secretPath, secretMap)
	} else {
		return nil, fmt.Errorf("kv_version must be v1 or v2")
	}

}

func KvGetSecret(client *vault.Client, kv_engine string, kv_version string, secretPath string) (*vault.KVSecret, error) {

	if kv_version == "v1" {
		secret, err := client.KVv1(kv_engine).Get(context.Background(), secretPath)
		if err != nil {
			return nil, fmt.Errorf("failed to obtain Vault secret: %w", err)
		}
		return secret, err
	} else if kv_version == "v2" {
		secret, err := client.KVv2(kv_engine).Get(context.Background(), secretPath)
		if err != nil {
			return nil, fmt.Errorf("failed to obtain Vault secret: %w", err)
		}
		return secret, err
	} else {
		return nil, fmt.Errorf("kv_version must be v1 or v2")
	}
}

func KvDeleteSecret(client *vault.Client, kv_engine string, kv_version string, secretPath string) error {
	if kv_version == "v1" {
		err := client.KVv1(kv_engine).Delete(context.Background(), secretPath)
		return err
	} else if kv_version == "v2" {
		err := client.KVv2(kv_engine).Delete(context.Background(), secretPath)
		return err
	} else {
		return fmt.Errorf("kv_version must be v1 or v2")
	}
}
func KvGetSecretPaths(client *vault.Client, kv_engine string, kv_version string, rootpath string) ([]string, error) {

	// define a var for the recursive function
	var listwalk func(kv_version string, subpath string) ([]string, error)
	// define the recursive function
	listwalk = func(kv_version string, subpath string) ([]string, error) {
		pathSliceRtn := make([]string, 0, 0)

		var ss *vault.Secret
		var err error

		if kv_version == "v1" {
			ss, err = client.Logical().ListWithContext(context.Background(), kv_engine+"/"+subpath)
		} else if kv_version == "v2" {
			ss, err = client.Logical().ListWithContext(context.Background(), kv_engine+"/metadata/"+subpath)
		} else {
			return nil, fmt.Errorf("kv_version must be v1 or v2")
		}

		// fmt.Printf("\ndata=%v", ss.Data)
		if ss == nil || err != nil {
			return nil, fmt.Errorf("failed to read List: %w", err)
		}

		for _, pathIface := range ss.Data {
			pathSlice := pathIface.([]interface{})
			for _, path := range pathSlice {
				pathStr := fmt.Sprint(path)
				if strings.HasSuffix(pathStr, "/") {
					// make a recursive call with the new 'root'
					paths, _ := listwalk(kv_version, subpath+pathStr)
					pathSliceRtn = append(pathSliceRtn, paths...)
				} else {
					pathSliceRtn = append(pathSliceRtn, subpath+pathStr)
				}
			}
		}
		return pathSliceRtn, nil
	}

	// call the recursive function with an initial empty subdir (as we want to start from the 'root' of the secret engine)
	pathSliceOut, err := listwalk(kv_version, rootpath)

	return pathSliceOut, err
}

func KvCreateHttpClient() *retryablehttp.Client {
	var tr *http.Transport
	tr = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{Transport: tr}
	client := retryablehttp.NewClient()
	client.HTTPClient = httpClient
	client.RetryMax = 10                    // max 10 retries
	client.RetryWaitMax = 300 * time.Second // max 5 mins between retries
	return client
}

func KvGoDoHttp(inputData map[string]interface{}, url string, method string, bodyMap map[string]interface{}, token string) error {

	client := KvCreateHttpClient()
	payloadBytes, err := json.Marshal(inputData)
	if err != nil {
		hclog.L().Error("goDoHttp json.Marshal Error=%v\n", err)
		return err
	}
	inputBody := bytes.NewReader(payloadBytes)

	var req *retryablehttp.Request
	if method == "GET" {
		req, err = retryablehttp.NewRequest(http.MethodGet, url, nil)
	} else {
		// method == "POST"
		req, err = retryablehttp.NewRequest(http.MethodPost, url, inputBody)
	}

	if err != nil {
		hclog.L().Error("goDoHttp http.NewRequest Error=%v\n", err)
		return err
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		hclog.L().Error("goDoHttp client.Do Error=%v\n", err)
		return err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		hclog.L().Error("goDoHttp io.ReadAll Error=%v\n", err)
		return err
	}

	err = json.Unmarshal([]byte(body), &bodyMap)
	if err != nil {
		hclog.L().Error("goDoHttp Unmarshall Error=%v\n", err)
		return err
	}
	return nil
}

type VaultClientWrapper interface {
	Write(path string, data map[string]interface{}) (*vault.Secret, error)
	GetClient() *vault.Client
}
type VaultClientWrapperImpl struct {
	Client *vault.Client
}

func (w VaultClientWrapperImpl) Write(path string, data map[string]interface{}) (*vault.Secret, error) {
	return (*w.Client).Logical().Write(path, data)
}
func (w VaultClientWrapperImpl) GetClient() *vault.Client {
	return w.Client
}

type DecryptedKVKey struct {
	Plaintext string `json:"plaintext"`
}
type EncryptedKVKey struct {
	Ciphertext string `json:"ciphertext"`
}

// type OptionsResolver func(*KVOptions) error
// type ClientResolver func(OptionsResolver) (*vault.Client, error)

func UnwrapKeyset(client *VaultClientWrapper, encryptedKVKey EncryptedKVKey, kvTransitKey string, kvTransitEngine string) (string, error) {
	decryptedKey, err := KVTransitDecrypt(client, encryptedKVKey, kvTransitKey, kvTransitEngine)
	if err != nil {
		return "", err
	}
	return decryptedKey.Plaintext, nil
}
func WrapKeyset(client *VaultClientWrapper, rawKeyset string, kvTransitKey string, kvTransitEngine string) (string, error) {
	encryptedKeyset, err := KVTransitEncrypt(client, rawKeyset, kvTransitKey, kvTransitEngine)
	if err != nil {
		return "", err
	}
	return encryptedKeyset.Ciphertext, nil
}
func KVTransitEncrypt(c *VaultClientWrapper, rawKeyset string, kvTransitKey string, kvTransitEngine string) (EncryptedKVKey, error) {
	base64Keyset := base64.StdEncoding.EncodeToString([]byte(rawKeyset))

	dataToEncrypt := map[string]interface{}{
		"plaintext": base64Keyset,
	}

	if kvTransitEngine == "" {
		kvTransitEngine = "transit"
	}

	// Use Transit KV engine to encrypt the data
	encrypted, err := (*c).Write(kvTransitEngine+"/encrypt/"+kvTransitKey, dataToEncrypt)
	if err != nil {
		return EncryptedKVKey{}, nil
	}

	cipherText, ok := encrypted.Data["ciphertext"].(string)
	if !ok {
		hclog.L().Error("ciphertext not found in Vault secret")
		return EncryptedKVKey{}, nil
	}

	secretData := EncryptedKVKey{
		Ciphertext: cipherText,
	}

	return secretData, nil
}
func KVTransitDecrypt(c *VaultClientWrapper, encrypted EncryptedKVKey, kvTransitKey string, kvTransitEngine string) (DecryptedKVKey, error) {

	if kvTransitEngine == "" {
		kvTransitEngine = "transit"
	}

	// Use Transit KV engine to decrypt the data
	decrypted, err := (*c).Write(kvTransitEngine+"/decrypt/"+kvTransitKey, map[string]interface{}{
		"ciphertext": encrypted.Ciphertext,
	})

	if err != nil {
		return DecryptedKVKey{}, fmt.Errorf("failed to obtain Vault secret: %w", err)
	}

	var retrievedData DecryptedKVKey
	retrievedData.Plaintext = decrypted.Data["plaintext"].(string)

	return retrievedData, nil
}

func DeriveKeyName(namespace string, keyname string, keyjson string) (string, error) {
	newkeyname := ""

	// validate the key
	kh, err := aeadutils.ValidateKeySetJson(keyjson)
	if err != nil {
		log.Fatal(err)
	}

	// namespace example would be "kms/XX"
	_, lm, found := strings.Cut(namespace, "/")
	if !found {
		lm = "XXX"
	}

	lmUpper := strings.ToUpper(lm)
	keynameUpper := strings.ToUpper(keyname)

	ksi := kh.KeysetInfo()
	ki := ksi.KeyInfo[len(ksi.KeyInfo)-1]
	keyTypeURL := ki.GetTypeUrl()
	keyType := ""
	// fmt.Printf("\n\nkeyTypeURL: %s\n", keyTypeURL)
	if keyTypeURL == "type.googleapis.com/google.crypto.tink.AesSivKey" {
		keyType = "SIV"
	} else if keyTypeURL == "type.googleapis.com/google.crypto.tink.AesGcmKey" {
		keyType = "GCM"
	}
	newkeyname = lmUpper + "_DEK_" + keynameUpper + "_AES256_" + keyType

	return newkeyname, nil
}
func DeriveKVKeyName(namespace string, keyname string, keyjson string) (string, error) {
	newkeyname := ""

	// validate the key
	kh, err := aeadutils.ValidateKeySetJson(keyjson)
	if err != nil {
		log.Fatal(err)
	}

	// namespace example would be "kms/XX"
	keynameLower := strings.ToLower(keyname)

	ksi := kh.KeysetInfo()
	ki := ksi.KeyInfo[len(ksi.KeyInfo)-1]
	keyTypeURL := ki.GetTypeUrl()
	keyType := ""
	// fmt.Printf("\n\nkeyTypeURL: %s\n", keyTypeURL)
	if keyTypeURL == "type.googleapis.com/google.crypto.tink.AesSivKey" {
		keyType = "siv"
	} else if keyTypeURL == "type.googleapis.com/google.crypto.tink.AesGcmKey" {
		keyType = "gcm"
	}
	secretParts := strings.Split(keynameLower, "_")
	newkeyname = keyType + "/" + secretParts[2]

	return newkeyname, nil
}

// func kvGetClientWithIAMrole(vault_addr string, namespace string, vaultApproleId string, vault_iam_role string, vault_kv_role string) (*vault.Client, string, error) {

// 	// 1. Get the SA we are working as
// 	saEmail, projectId, err := getMetadataInfo()
// 	if err != nil {
// 		fmt.Printf("oops error from getMetadataInfo=%s", err.Error())
// 		log.Fatal()
// 	}
// 	fmt.Printf("\nsaEmail=%s ProjectId=%s\n", saEmail, projectId)

// 	// 2. use the SA and IAM role to generate a token for vault
// 	_, token, err := getVaultTokenGCPAuthIAM(saEmail, vault_addr, vault_iam_role)
// 	if err != nil {
// 		fmt.Printf("oops error from getVaultTokenGCPAuthIAM=%s", err.Error())
// 		log.Fatal()
// 	}
// 	fmt.Printf("\ntoken from getVaultTokenGCPAuthIAM=%s\n", token)

// 	// 3. use the token (scoped to only be able to generate a secret for an app role, to create a new secretid)
// 	newSecretId, err := createSecretIdForRole(vault_addr, token, vault_kv_role)
// 	if err != nil {
// 		fmt.Printf("oops error from createSecretIdForRole=%s", err.Error())
// 		log.Fatal()
// 	}
// 	fmt.Printf("\nnewSecretId from createSecretIdForRole=%s\n", newSecretId)

// 	// 4. use the original approle and new secret id to generate a new token
// 	_, newtoken, err := kvGetClientWithApprole(vault_addr, "", vaultApproleId, newSecretId)
// 	if err != nil {
// 		fmt.Printf("oops error from kvGetClientWithApprole=%s", err.Error())
// 		log.Fatal()
// 	}

// 	fmt.Printf("\nNEW Token=%v", newtoken)

// 	//5. manually check the scope of the new token
// 	// vault login (new token)
// 	return nil, newtoken, nil
// }

func getMetadataInfo() (string, string, error) {
	url := "http://metadata.google.internal/computeMetadata/v1/project/project-id"
	projectID, err := callMetadataServer(url)
	if err != nil {
		return "", "", fmt.Errorf("Error: unable to contact http://metadata.google.internal: %s", err)
	}

	url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
	saEmail, err := callMetadataServer(url)
	if err != nil {
		return "", "", fmt.Errorf("Error: unable to contact http://metadata.google.internal: %s", err)
	}

	return saEmail, projectID, nil
}
func callMetadataServer(metadata_url string) (string, error) {
	req, err := http.NewRequest("GET", metadata_url, nil)
	req.Header.Set("Metadata-Flavor", "Google")

	// proxyurlStr := os.Getenv("https_proxy")
	// proxyurlStr = ""

	var tr *http.Transport
	// if proxyurlStr != "" {
	// 	proxyUrl, _ := url.Parse(proxyurlStr)

	// 	tr = &http.Transport{
	// 		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	// 		Proxy:           http.ProxyURL(proxyUrl),
	// 	}
	// } else {

	tr = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// }

	client := &http.Client{Transport: tr}

	// client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	return string(body), nil
}

func GetMetadataInfo() (string, string, error) {
	url := "http://metadata.google.internal/computeMetadata/v1/project/project-id"
	projectID, err := callMetadataServer(url)
	if err != nil {
		return "", "", fmt.Errorf("Error: unable to contact http://metadata.google.internal: %s", err)
	}

	url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
	saEmail, err := callMetadataServer(url)
	if err != nil {
		return "", "", fmt.Errorf("Error: unable to contact http://metadata.google.internal: %s", err)
	}

	return saEmail, projectID, nil
}

func getVaultTokenGCPAuthIAM(serviceAccount string, vaultAddress string, vaultIAM string) (*vault.Client, string, error) {
	config := vault.DefaultConfig()

	// Override default vaultAddress
	config.Address = vaultAddress

	// Initialise Vault client
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, "", fmt.Errorf("unable to initialize Vault client: %w", err)
	}

	// auth.WithIAMAuth option uses the IAM-style authentication
	fmt.Printf("\ngetVaultTokenGCPAuthIAM(serviceAccount=%s, vaultAddress=%s, vaultIAM=%s)", serviceAccount, vaultAddress, vaultIAM)
	gcpAuth, err := authgcp.NewGCPAuth(
		vaultIAM,
		authgcp.WithIAMAuth(serviceAccount),
	)
	if err != nil {
		return nil, "", fmt.Errorf("unable to initialize GCP auth method: %w", err)
	}

	// Login to Vault to retrieve valid token
	authInfo, err := client.Auth().Login(context.Background(), gcpAuth)
	if err != nil {
		return nil, "", fmt.Errorf("unable to login to GCP auth method: %w", err)
	}
	if authInfo == nil {
		return nil, "", fmt.Errorf("login response did not return client token")
	}

	ti, err := authInfo.TokenID()

	client.SetToken(ti)
	return client, ti, nil
}

func createSecretIdForRole(vaulturl string, token string, approle string) (string, error) {

	var tr *http.Transport
	proxyurlStr := os.Getenv("https_proxy")

	if proxyurlStr != "" {
		proxyUrl, _ := url.Parse(proxyurlStr)

		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyURL(proxyUrl),
		}
	} else {

		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	httpClient := &http.Client{Transport: tr}
	client := retryablehttp.NewClient()
	client.HTTPClient = httpClient
	client.RetryMax = 10                    // max 10 retries
	client.RetryWaitMax = 300 * time.Second // max 5 mins between retries

	url := vaulturl + "/v1/auth/approle/role/" + approle + "/secret-id"
	req, err := retryablehttp.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		fmt.Printf("oops error from retryablehttp.NewRequest=%s", err.Error())
		hclog.L().Error("\nfailed to initialize AppRole auth method: %w", err)
		return "", err
	}
	req.Header.Set("X-Vault-Token", token)
	// req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("oops error from client.Do=%s", err.Error())
		return "", err
	}

	defer resp.Body.Close()

	hclog.L().Error("resp=%v", resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("goDoHttp io.ReadAll Error=%v\n", err)
	}

	bodyMap := map[string]interface{}{}

	err = json.Unmarshal([]byte(body), &bodyMap)
	if err != nil {
		fmt.Printf("goDoHttp Unmarshall Error=%v\n", err)
	}
	hclog.L().Error("\nbodymap=%v", bodyMap)

	dataMap := bodyMap["data"]
	// dataMapDeets := map[string]interface{}{}
	dataMapDeets := dataMap.(map[string]interface{})
	hclog.L().Error("\nnewSecretId=%v", dataMapDeets["secret_id"])
	si := fmt.Sprintf("%s", dataMapDeets["secret_id"])

	return si, nil
}
