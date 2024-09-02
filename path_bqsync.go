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

	keysToSync := data.Raw

	keysMap := make(map[string]interface{})

	for keyField, encryptionKey := range AEAD_CONFIG.Items() {
		fieldName := fmt.Sprintf("%v", keyField)
		keyStr := fmt.Sprintf("%v", encryptionKey)
		if !strings.Contains(keyStr, "primaryKeyId") {
			continue
		}

		if len(keysToSync) != 0 {
			if _, okay := keysToSync[fieldName]; !okay {
				continue
			}
		}

		// if kvKeysExists && !slices.Contains(paths["keys"], fieldName) {
		// 	continue
		// }
		keysMap[fieldName] = encryptionKey
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
