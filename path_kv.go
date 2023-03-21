package aeadplugin

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathReadKV(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	m, _ := b.readKV(ctx, req.Storage)

	return &logical.Response{
		Data: m,
	}, nil
}

func (b *backend) readKV(ctx context.Context, s logical.Storage) (map[string]interface{}, error) {

	consulKV := make(map[string]interface{})
	entry, err := s.Get(ctx, "testpath/data/foo")

	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	if err := entry.DecodeJSON(&consulKV); err != nil {
		return nil, err
	}
	return consulKV, nil
}
