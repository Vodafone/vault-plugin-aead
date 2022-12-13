package aeadplugin

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	backoff "github.com/cenkalti/backoff/v4"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-retryablehttp"
)

func CreateInsecureHandleAndAead(rawKeyset string) (*keyset.Handle, tink.AEAD, error) {
	r := keyset.NewJSONReader(bytes.NewBufferString(rawKeyset))

	kh, err := insecurecleartextkeyset.Read(r)

	if err != nil {
		hclog.L().Error("CreateInsecureHandleAndAead: Failed to get the keyset:  %v", err)
	}
	a, err := aead.New(kh)
	if err != nil {
		hclog.L().Error("CreateInsecureHandleAndAead:Failed to get the key:  %v", err)
	}
	return kh, a, nil
}

func CreateInsecureHandleAndDeterministicAead(rawKeyset string) (*keyset.Handle, tink.DeterministicAEAD, error) {
	r := keyset.NewJSONReader(bytes.NewBufferString(rawKeyset))

	kh, err := insecurecleartextkeyset.Read(r)

	if err != nil {
		hclog.L().Error("CreateInsecureHandleAndDeterministicAead: Failed to get the keyset:  %v", err)
	}
	d, err := daead.New(kh)
	if err != nil {
		hclog.L().Error("CreateInsecureHandleAndDeterministicAead: Failed to get the key:  %v", err)
	}
	return kh, d, nil
}

func ExtractInsecureKeySetFromKeyhandle(kh *keyset.Handle) (string, error) {
	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)

	err := insecurecleartextkeyset.Write(kh, w)

	if err != nil {
		hclog.L().Error("cannot write keyset:  %v", err)
		return "", nil
	}
	return buf.String(), nil
}

func CreateNewDeterministicAead() (*keyset.Handle, tink.DeterministicAEAD, error) {
	kh, err := keyset.NewHandle(daead.AESSIVKeyTemplate())
	if err != nil {
		hclog.L().Error("cannot create key handle:  %v", err)
	}

	d, err := daead.New(kh)
	if err != nil {
		hclog.L().Error("cannot get det aead:  %v", err)
	}
	return kh, d, nil
}

func CreateNewAead() (*keyset.Handle, tink.AEAD, error) {
	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		hclog.L().Error("cannot create new aead keyhandle:  %v", err)
		return nil, nil, err
	}

	a, err := aead.New(kh)
	if err != nil {
		hclog.L().Error("cannot create new aead key:  %v", err)
		return nil, nil, err
	}
	return kh, a, nil
}

func RotateKeys(kh *keyset.Handle, deterministic bool) {
	manager := keyset.NewManagerFromHandle(kh)
	if deterministic {
		manager.Rotate(daead.AESSIVKeyTemplate())
	} else {
		manager.Rotate(aead.AES256GCMKeyTemplate())
	}
}

func IsKeyHandleDeterministic(kh *keyset.Handle) bool {
	// the alt to this is to convert the key info tom json and trawl through it
	// i hate this, but i don't see an alternative atm

	// also, it seems you cannot have a keyset that has both deterministic and non deterministic types
	deterministic := false

	// is the key AEAD
	_, err := aead.New(kh)
	if err != nil {
		// is the key DAEAD
		_, err := daead.New(kh)
		if err != nil {
			panic(err)
		} else {
			deterministic = true
		}
	}
	return deterministic
}

func PivotMap(originalMap map[string]map[string]string, newMap map[string]map[string]string) {
	for k, v := range originalMap {
		// fmt.Printf("\nk=%v v=%v", k, v)
		for ki, vi := range v {
			// fmt.Printf("\nki=%v vi=%v", ki, vi)
			newInnerMap, ok := newMap[ki]
			if ok {
				newInnerMap[k] = vi
				newMap[ki] = newInnerMap
			} else {
				newInnerMap := make(map[string]string)
				newInnerMap[k] = vi
				newMap[ki] = newInnerMap
			}
		}
	}
}

func PivotMapInt(mo map[string]interface{}, nmo map[string]interface{}) {
	for k, v := range mo {
		// fmt.Printf("\nk=%v v=%v", k, v)
		vm, ok := v.(map[string]interface{})
		if !ok {
			hclog.L().Error("cannot create new aead keyhandleouter assertion failed")
		}
		for ki, vi := range vm {
			// fmt.Printf("\nki=%v vi=%v", ki, vi)

			nmi, ok := nmo[ki]

			if ok {
				nmi2, ok2 := nmi.(map[string]interface{})
				if !ok2 {
					fmt.Printf("inner assertion failed")
				}
				nmi2[k] = vi
				nmo[ki] = nmi2
			} else {
				nmi2 := make(map[string]interface{})
				nmi2[k] = vi
				nmo[ki] = nmi2
			}
		}
	}
}

type KeySetStruct struct {
	PrimaryKeyID int `json:"primaryKeyId"`
	Key          []struct {
		KeyData struct {
			TypeURL         string `json:"typeUrl"`
			Value           string `json:"value"`
			KeyMaterialType string `json:"keyMaterialType"`
		} `json:"keyData"`
		Status           string `json:"status"`
		KeyID            int    `json:"keyId"`
		OutputPrefixType string `json:"outputPrefixType"`
	} `json:"key"`
}

func (k *KeySetStruct) GetKeyID(keyId int) (int, error) {
	for i, key := range k.Key {
		if key.KeyID == keyId {
			return i, nil
		}
	}
	return -1, fmt.Errorf("could not find key based on KeyID")
}
func (k *KeySetStruct) UpdateExistingKeyStatus(keyID int, enabled string) {
	index, err := k.GetKeyID(keyID)
	if err != nil || index == -1 {
		hclog.L().Error("no KeyID found")
		return
	}
	k.Key[index].Status = enabled
}

func (k *KeySetStruct) UpdateExistingKeyMaterial(keyID int, keyMaterial string) {
	index, err := k.GetKeyID(keyID)
	if err != nil || index == -1 {
		hclog.L().Error("no KeyID found")
		return
	}
	k.Key[index].KeyData.Value = keyMaterial
}

func (k *KeySetStruct) UpdateExistingKeyID(keyID int, newkeyID int) {
	index, err := k.GetKeyID(keyID)
	if err != nil || index == -1 {
		hclog.L().Error("no KeyID found")
		return
	}
	k.Key[index].KeyID = newkeyID
	if k.PrimaryKeyID == keyID {
		k.PrimaryKeyID = newkeyID
	}
}

func (k *KeySetStruct) UpdateExistingPrimaryKeyID(keyID int) {
	index, err := k.GetKeyID(keyID)
	if err != nil || index == -1 {
		hclog.L().Error("no KeyID found")
		return
	}
	// we found a key so its valid
	k.PrimaryKeyID = keyID

}

func UpdateKeyStatus(kh *keyset.Handle, keyId string, status string) (*keyset.Handle, error) {
	// extract the JSON key that could be stored
	buf := new(bytes.Buffer)
	jsonWriter := keyset.NewJSONWriter(buf)

	insecurecleartextkeyset.Write(kh, jsonWriter)

	// unmarshall the keyset
	str := buf.String()
	var keySetStruct KeySetStruct
	err := json.Unmarshal([]byte(str), &keySetStruct)
	if err != nil {
		hclog.L().Error("failed to unmarshall the keyset")
		return nil, err
	}
	// update the status
	keyInt, _ := strconv.Atoi(keyId)
	keySetStruct.UpdateExistingKeyStatus(keyInt, status)

	// make the json again
	data, err := json.Marshal(keySetStruct)
	if err != nil {
		hclog.L().Error("failed to marshall the keyset")
		return nil, err
	}

	// make a key handle from the json, if it doesnt error, its still valid
	r := keyset.NewJSONReader(bytes.NewBufferString(string(data)))
	newkh, err := insecurecleartextkeyset.Read(r)
	if err != nil {
		hclog.L().Error("Failed to make a key handle from the json:  %v", err)
		return nil, err
	}

	return newkh, nil
}

func UpdateKeyMaterial(kh *keyset.Handle, keyId string, material string) (*keyset.Handle, error) {
	// extract the JSON key that could be stored
	buf := new(bytes.Buffer)
	jsonWriter := keyset.NewJSONWriter(buf)

	insecurecleartextkeyset.Write(kh, jsonWriter)

	// unmarshall the keyset
	str := buf.String()
	var keySetStruct KeySetStruct
	err := json.Unmarshal([]byte(str), &keySetStruct)
	if err != nil {
		hclog.L().Error("failed to unmarshall the keyset")
		return nil, err
	}
	// update the status
	keyInt, _ := strconv.Atoi(keyId)
	keySetStruct.UpdateExistingKeyMaterial(keyInt, material)

	// make the json again
	data, err := json.Marshal(keySetStruct)
	if err != nil {
		hclog.L().Error("failed to marshall the keyset")
		return nil, err
	}

	// make a key handle from the json, if it doesnt error, its still valid
	r := keyset.NewJSONReader(bytes.NewBufferString(string(data)))
	newkh, err := insecurecleartextkeyset.Read(r)
	if err != nil {
		hclog.L().Error("Failed to make a key handle from the json:  %v", err)
		return nil, err
	}

	return newkh, nil
}

func UpdateKeyID(kh *keyset.Handle, keyId string, newKeyId string) (*keyset.Handle, error) {
	// extract the JSON key that could be stored
	buf := new(bytes.Buffer)
	jsonWriter := keyset.NewJSONWriter(buf)

	insecurecleartextkeyset.Write(kh, jsonWriter)

	// unmarshall the keyset
	str := buf.String()
	var keySetStruct KeySetStruct
	err := json.Unmarshal([]byte(str), &keySetStruct)
	if err != nil {
		hclog.L().Error("failed to unmarshall the keyset")
		return nil, err
	}
	// update the status
	keyInt, _ := strconv.Atoi(keyId)
	newKeyInt, _ := strconv.Atoi(newKeyId)
	keySetStruct.UpdateExistingKeyID(keyInt, newKeyInt)

	// make the json again
	data, err := json.Marshal(keySetStruct)
	if err != nil {
		hclog.L().Error("failed to marshall the keyset")
		return nil, err
	}

	// make a key handle from the json, if it doesnt error, its still valid
	r := keyset.NewJSONReader(bytes.NewBufferString(string(data)))
	newkh, err := insecurecleartextkeyset.Read(r)
	if err != nil {
		hclog.L().Error("Failed to make a key handle from the json:  %v", err)
		return nil, err
	}

	return newkh, nil

}

func UpdatePrimaryKeyID(kh *keyset.Handle, keyId string) (*keyset.Handle, error) {
	// extract the JSON key that could be stored
	buf := new(bytes.Buffer)
	jsonWriter := keyset.NewJSONWriter(buf)

	insecurecleartextkeyset.Write(kh, jsonWriter)

	// unmarshall the keyset
	str := buf.String()
	var keySetStruct KeySetStruct
	err := json.Unmarshal([]byte(str), &keySetStruct)
	if err != nil {
		hclog.L().Error("failed to unmarshall the keyset")
		return nil, err
	}
	// update the status
	keyInt, _ := strconv.Atoi(keyId)
	keySetStruct.UpdateExistingPrimaryKeyID(keyInt)

	// make the json again
	data, err := json.Marshal(keySetStruct)
	if err != nil {
		hclog.L().Error("failed to marshall the keyset")
		return nil, err
	}

	// make a key handle from the json, if it doesnt error, its still valid
	r := keyset.NewJSONReader(bytes.NewBufferString(string(data)))
	newkh, err := insecurecleartextkeyset.Read(r)
	if err != nil {
		hclog.L().Error("Failed to make a key handle from the json:  %v", err)
		return nil, err
	}

	return newkh, nil
}

func ValidateKeySetJson(keySetJson string) error {
	r := keyset.NewJSONReader(bytes.NewBufferString(string(keySetJson)))
	_, err := insecurecleartextkeyset.Read(r)
	if err != nil {
		hclog.L().Error("Failed to make a key handle from the json:  %v", err)
		return err
	}
	return nil
}

func isEncryptionJsonKey(keyStr string) bool {
	//TODO find better way to check this
	return strings.Contains(keyStr, "primaryKeyId")
}

func isKeyJsonDeterministic(encryptionkey interface{}) (string, bool) {
	encryptionKeyStr := fmt.Sprintf("%v", encryptionkey)
	deterministic := false
	if strings.Contains(encryptionKeyStr, "AesSivKey") {
		deterministic = true
	}
	return encryptionKeyStr, deterministic
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

func muteKeyMaterial(theKey string) string {
	type jsonKey struct {
		Key []struct {
			KeyData struct {
				Value string `json:"value"`
			} `json:"keyData"`
		} `json:"key"`
	}
	var resp jsonKey
	err := json.Unmarshal([]byte(theKey), &resp)
	if err != nil {
		panic(err)
	}
	mutedMaterial := theKey
	for _, key := range resp.Key {
		mutedMaterial = strings.Replace(mutedMaterial, key.KeyData.Value, "***", -1)
	}
	return mutedMaterial
}

func createHttpClient(httpProxy string) *retryablehttp.Client {
	var tr *http.Transport
	if httpProxy == "" {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		proxyUrl, _ := url.Parse(httpProxy)
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyURL(proxyUrl),
		}
	}

	httpClient := &http.Client{Transport: tr}
	client := retryablehttp.NewClient()
	client.HTTPClient = httpClient
	client.RetryMax = 10                    // max 10 retries
	client.RetryWaitMax = 300 * time.Second // max 5 mins between retries
	return client
}

func goDoHttp(inputData map[string]interface{}, url string, bodyMap map[string]interface{}, httpProxy string, token string) error {

	client := createHttpClient(httpProxy)
	payloadBytes, err := json.Marshal(inputData)
	if err != nil {
		fmt.Printf("goDoHttp json.Marshal Error=%v\n", err)
		return err
	}
	inputBody := bytes.NewReader(payloadBytes)

	req, err := retryablehttp.NewRequest(http.MethodPost, url, inputBody)

	if err != nil {
		fmt.Printf("goDoHttp http.NewRequest Error=%v\n", err)
		return err
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("goDoHttp client.Do Error=%v\n", err)
		return err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("goDoHttp io.ReadAll Error=%v\n", err)
		return err
	}

	err = json.Unmarshal([]byte(body), &bodyMap)
	if err != nil {
		fmt.Printf("goDoHttp Unmarshall Error=%v\n", err)
		return err
	}
	return nil
}

func EncryptOrDecryptData(url string, inputMap map[string]interface{}, httpProxy string, token string) (map[string]interface{}, error) {

	response := make(map[string]interface{})
	emptyMap := make(map[string]interface{})
	data := make(map[string]interface{})
	ok := true
	i := 0

	// I absolutely hate that you can only wrap a function with no args that returns an error "func() error" here
	// so I have to rely on variable scope, but life is too short
	operation := func() error {
		// if i > 0 {
		// 	fmt.Printf("Retry=%v encryptOrDecryptData\n", i)
		// }
		i++
		err := goDoHttp(inputMap, url, response, httpProxy, token)
		if err != nil {
			fmt.Printf("encryptOrDecryptData Try=%v Error after goDoHttp=%v\n", i, err)
			return err
		}
		data, ok = response["data"].(map[string]interface{})
		if !ok {
			errors, ok := response["errors"].([]interface{})
			if ok {
				// we have errors from vault
				fmt.Printf("encryptOrDecryptData Try=%v Vault Response=%v\n", i, errors)
				return fmt.Errorf("error response from vault %v", errors)
			} else {
				// we have errors but no idea why
				fmt.Printf("encryptOrDecryptData Try=%v Vault Response - no idea\n", i)
				return fmt.Errorf("error converting response to map[string]interface{}")
			}
		}
		return nil // or an error
	}
	xbo := backoff.NewExponentialBackOff()
	xbo.MaxElapsedTime = 15 * time.Minute
	err := backoff.Retry(operation, xbo)
	if err != nil {
		// Handle error.
		return emptyMap, err
	}

	return data, nil
}
