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
				for configKey := range AEAD_CONFIG.Items() {
					// Match keys that start with the pattern
					if strings.HasPrefix(configKey, pattern) || strings.HasPrefix(configKey, "gcm/"+pattern) || strings.HasPrefix(configKey, "siv/"+pattern) {
						keysToProcess = append(keysToProcess, configKey)
					}
				}
			} else {
				// Regular key - find all variants (exact, gcm/, siv/)
				actualKeyNames := b.findAllKeysWithPrefix(fieldName)
				keysToProcess = append(keysToProcess, actualKeyNames...)
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

	// Validate that required datasets exist before processing
	var validKeys []string
	var skippedKeys []string
	for keyName := range keysMap {
		// Check if this key will have required datasets
		// Extract category (key name without prefix)
		categoryName := aeadutils.RemoveKeyPrefix(keyName)
		categoryName = strings.Replace(categoryName, "-", "_", -1)
		
		// Check if at least one region's decrypt dataset exists
		hasDecryptDataset := false
		for _, region := range []string{"eu", "europe_west1", "europe_west2", "europe_west3"} {
			decryptDatasetId := fmt.Sprintf("vfpf1_dh_lake_xregion_pf1_%s_aead_decrypt_%s_s", categoryName, region)
			if _, exists := datasets[decryptDatasetId]; exists {
				hasDecryptDataset = true
				break
			}
		}
		
		if !hasDecryptDataset {
			hclog.L().Warn("No decrypt dataset found for key: " + keyName)
			skippedKeys = append(skippedKeys, keyName)
			continue
		}
		validKeys = append(validKeys, keyName)
	}

	// Process only valid keys
	var wg sync.WaitGroup
	syncedCount := 0
	for _, keyName := range validKeys {
		encryptionKey := keysMap[keyName]

		encryptionKeyStr, deterministic := aeadutils.IsKeyJsonDeterministic(encryptionKey)
		if deterministic {
			kh, _, err := aeadutils.CreateInsecureHandleAndDeterministicAead(encryptionKeyStr)
			if err != nil {
				hclog.L().Error("failed to create deterministic key handle for: " + keyName)
				continue
			}
			syncedCount++
			wg.Add(1)
			go func() {
				defer wg.Done()
				bqutils.DoBQSync(ctx, kh, keyName, true, AEAD_CONFIG, datasets)
			}()
		} else {
			kh, _, err := aeadutils.CreateInsecureHandleAndAead(encryptionKeyStr)
			if err != nil {
				hclog.L().Error("failed to create non deterministic key handle for: " + keyName)
				continue
			}
			syncedCount++
			wg.Add(1)
			go func() {
				defer wg.Done()
				bqutils.DoBQSync(ctx, kh, keyName, false, AEAD_CONFIG, datasets)
			}()
		}
	}
	wg.Wait()

	return &logical.Response{
		Data: map[string]interface{}{
			"synced_keys":   syncedCount,
			"skipped_keys":  len(skippedKeys),
			"skipped_list":  skippedKeys,
		},
	}, nil
}
