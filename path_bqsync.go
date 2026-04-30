package aeadplugin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Vodafone/vault-plugin-aead/aeadutils"
	"github.com/Vodafone/vault-plugin-aead/bqutils"
	"github.com/google/tink/go/keyset"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathBQKeySync(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// retrieve the config from storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	// Add timeout protection - prevent indefinite hanging (5 minutes)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	keysMap := make(map[string]interface{})
	var keysToProcess []string
	var notFoundKeys []string

	// Check if specific keys were requested for syncing
	keysParam := data.Get("keys")
	if keysParam != nil && keysParam.(string) != "" {
		// Parse comma-separated list of keys and find all their variants
		keysList := strings.Split(keysParam.(string), ",")
		for _, requestedKeyName := range keysList {
			fieldName := strings.TrimSpace(requestedKeyName)
			
			// Check if this is a wildcard pattern (contains *)
			if strings.Contains(fieldName, "*") {
				// Wildcard matching: find all keys matching the pattern
				pattern := strings.Replace(fieldName, "*", "", -1) // Remove * to get prefix
				matchFound := false
				for configKey := range AEAD_CONFIG.Items() {
					// Match keys that start with the pattern
					if strings.HasPrefix(configKey, pattern) || strings.HasPrefix(configKey, "gcm/"+pattern) || strings.HasPrefix(configKey, "siv/"+pattern) {
						keysToProcess = append(keysToProcess, configKey)
						matchFound = true
					}
				}
				if !matchFound {
					notFoundKeys = append(notFoundKeys, fieldName)
				}
			} else {
				// Regular key - find all variants (exact, gcm/, siv/)
				actualKeyNames := b.findAllKeysWithPrefix(fieldName)
				if len(actualKeyNames) == 0 {
					notFoundKeys = append(notFoundKeys, fieldName)
				} else {
					keysToProcess = append(keysToProcess, actualKeyNames...)
				}
			}
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

	// Process all requested keys
	var wg sync.WaitGroup
	syncedCount := 0
	var syncedKeys []string
	var failedKeys []map[string]string
	for keyName, encryptionKey := range keysMap {

		encryptionKeyStr, deterministic := aeadutils.IsKeyJsonDeterministic(encryptionKey)
		if deterministic {
			kh, _, err := aeadutils.CreateInsecureHandleAndDeterministicAead(encryptionKeyStr)
			if err != nil {
				hclog.L().Error("failed to create deterministic key handle for: " + keyName)
				failedKeys = append(failedKeys, map[string]string{
					"key":   keyName,
					"error": "failed to create key handle: " + err.Error(),
				})
				continue
			}
			syncedCount++
			syncedKeys = append(syncedKeys, keyName)
			wg.Add(1)
			go func(name string, keyHandle *keyset.Handle) {
				defer wg.Done()
				bqutils.DoBQSync(ctx, keyHandle, name, true, AEAD_CONFIG, datasets)
			}(keyName, kh)
		} else {
			kh, _, err := aeadutils.CreateInsecureHandleAndAead(encryptionKeyStr)
			if err != nil {
				hclog.L().Error("failed to create non deterministic key handle for: " + keyName)
				failedKeys = append(failedKeys, map[string]string{
					"key":   keyName,
					"error": "failed to create key handle: " + err.Error(),
				})
				continue
			}
			syncedCount++
			syncedKeys = append(syncedKeys, keyName)
			wg.Add(1)
			go func(name string, keyHandle *keyset.Handle) {
				defer wg.Done()
				bqutils.DoBQSync(ctx, keyHandle, name, false, AEAD_CONFIG, datasets)
			}(keyName, kh)
		}
	}
	wg.Wait()

	response := map[string]interface{}{
		"synced_keys": syncedCount,
		"failed_keys": len(failedKeys),
	}

	if len(syncedKeys) > 0 {
		response["synced_list"] = syncedKeys
	}
	
	if len(failedKeys) > 0 {
		response["failed_list"] = failedKeys
	}
	
	if len(notFoundKeys) > 0 {
		response["not_found_keys"] = len(notFoundKeys)
		response["not_found_list"] = notFoundKeys
	}

	return &logical.Response{
		Data: response,
	}, nil
}
