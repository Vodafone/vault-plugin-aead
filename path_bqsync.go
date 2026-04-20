package aeadplugin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/Vodafone/vault-plugin-aead/aeadutils"
	"github.com/Vodafone/vault-plugin-aead/bqutils"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathBQKeySync(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	keysMap := make(map[string]interface{})
	var keysToProcess []string

	// Check if specific keys were requested for syncing
	keysParam := data.Get("keys")
	if keysParam != nil && keysParam.(string) != "" {
		// Parse comma-separated list of keys and find all their variants
		keysList := strings.Split(keysParam.(string), ",")
		for _, requestedKeyName := range keysList {
			fieldName := strings.TrimSpace(requestedKeyName)
			// Find all key variants matching this name (exact, gcm/, siv/)
			actualKeyNames := b.findAllKeysWithPrefix(fieldName)
			keysToProcess = append(keysToProcess, actualKeyNames...)
		}
	} else {
		// No specific keys requested - process all valid keys
		for keyField, encryptionKey := range AEAD_CONFIG.Items() {
			fieldName := fmt.Sprintf("%v", keyField)
			keyStr := fmt.Sprintf("%v", encryptionKey)
			// Only include valid keysets (must contain "primaryKeyId")
			if strings.Contains(keyStr, "primaryKeyId") {
				keysToProcess = append(keysToProcess, fieldName)
			}
		}
	}

	// Build the keysMap from keysToProcess
	for _, keyName := range keysToProcess {
		encryptionKey, ok := AEAD_CONFIG.Get(keyName)
		if ok {
			keysMap[keyName] = encryptionKey
		}
	}

	projectIdInterface, ok := AEAD_CONFIG.Get("BQ_PROJECT")
	projectId := fmt.Sprintf("%s", projectIdInterface)
	if !ok {
		return nil, &logical.KeyNotFoundError{
			Err: errors.New("No BQ_PROJECT"),
		}
	}

	datasets, err := bqutils.GetBQDatasets(ctx, projectId)
	if err != nil {
		hclog.L().Error("Failed to list Datasets")
		return nil, err
	}

	// hclog.L().Info("datasets: ", datasets)
	var wg sync.WaitGroup
	for fieldName, encryptionKey := range keysMap {

		encryptionKeyStr, deterministic := aeadutils.IsKeyJsonDeterministic(encryptionKey)
		if deterministic {
			kh, _, err := aeadutils.CreateInsecureHandleAndDeterministicAead(encryptionKeyStr)
			if err != nil {
				hclog.L().Error("failed to create deterministic key handle")
				return &logical.Response{
					Data: make(map[string]interface{}),
				}, err
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				bqutils.DoBQSync(ctx, kh, fieldName, true, AEAD_CONFIG, datasets)
			}()
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
			wg.Add(1)
			go func() {
				defer wg.Done()
				bqutils.DoBQSync(ctx, kh, fieldName, false, AEAD_CONFIG, datasets)
			}()
		}

	}
	wg.Wait()

	return nil, nil
}
