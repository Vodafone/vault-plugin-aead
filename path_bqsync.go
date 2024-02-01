package aeadplugin

import (
	"context"
	"fmt"
	"strings"

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

	for keyField, encryptionKey := range AEAD_CONFIG.Items() {
		fieldName := fmt.Sprintf("%v", keyField)
		keyStr := fmt.Sprintf("%v", encryptionKey)
		if !strings.Contains(keyStr, "primaryKeyId") {
			continue
		}

		encryptionKeyStr, deterministic := aeadutils.IsKeyJsonDeterministic(encryptionKey)
		if deterministic {
			kh, _, err := aeadutils.CreateInsecureHandleAndDeterministicAead(encryptionKeyStr)
			if err != nil {
				hclog.L().Error("failed to create deterministic key handle")
				return &logical.Response{
					Data: make(map[string]interface{}),
				}, err
			}
			bqutils.DoBQSync(kh, fieldName, true, AEAD_CONFIG)
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
			bqutils.DoBQSync(kh, fieldName, false, AEAD_CONFIG)
		}

	}

	return nil, nil
}
