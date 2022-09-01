package aeadplugin

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

// Factory creates a new usable instance of this secrets engine.
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, errors.Wrap(err, "failed to create factory")
	}
	return b, nil
}

// backend is the actual backend.
type backend struct {
	*framework.Backend

	clientMutex sync.RWMutex
}

// Backend creates a new backend.
func Backend(c *logical.BackendConfig) *backend {
	var b backend

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        backendHelp,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
		},

		/*
			curl -sk -X GET --header "X-Vault-Token: "${VAULT_TOKEN} ${VAULT_URL}/v1/sys/host-info
			PATHS Supported are
			info
				curl -sk -X GET --header "X-Vault-Token: "${VAULT_TOKEN} ${VAULT_URL}/v1/aead-secrets/info
			config
				curl -sk --header "X-Vault-Token: "${VAULT_TOKEN} --request POST ${VAULT_URL}/v1/aead-secrets/config -H "Content-Type: application/json" -d '{"key":"value"}'
				curl -sk -X GET --header "X-Vault-Token: "${VAULT_TOKEN} ${VAULT_URL}/v1/aead-secrets/config
			encrypt
				curl -sk --header "X-Vault-Token: "${VAULT_TOKEN} --request POST ${VAULT_URL}/v1/aead-secrets/encrypt -H "Content-Type: application/json" -d '{"fieldname":"plaintext"}'
			decrypt
				curl -sk --header "X-Vault-Token: "${VAULT_TOKEN} --request POST ${VAULT_URL}/v1/aead-secrets/decrypt -H "Content-Type: application/json" -d '{"fieldname":"cyphertext"}'
			rotate
				curl -sk --header "X-Vault-Token: "${VAULT_TOKEN} --request POST ${VAULT_URL}/v1/aead-secrets/rotate -H "Content-Type: application/json" -d '{"key":"value"}'
				curl -sk --header "X-Vault-Token: "${VAULT_TOKEN} --request POST ${VAULT_URL}/v1/aead-secrets/rotate
			createAEADkey
				curl -sk --header "X-Vault-Token: "${VAULT_TOKEN} --request POST ${VAULT_URL}/v1/aead-secrets/createAEADkey -H "Content-Type: application/json" -d '{"fieldname":"plaintext"}'
			createDAEADkey
				curl -sk --header "X-Vault-Token: "${VAULT_TOKEN} --request POST ${VAULT_URL}/v1/aead-secrets/createDAEADkey -H "Content-Type: application/json" -d '{"fieldname-det":"plaintext"}'
			keytypes
				curl -sk -X GET --header "X-Vault-Token: "${VAULT_TOKEN} ${VAULT_URL}/v1/aead-secrets/keytypes | jq
			bqsync
				curl -sk --header "X-Vault-Token: "${VAULT_TOKEN} --request POST ${VAULT_URL}/v1/aead-secrets/bqsync

			adding key-families:
				curl -sk --header "X-Vault-Token: "${VAULT_TOKEN} --request POST ${VAULT_URL}/v1/aead-secrets/createAEADkey -H "Content-Type: application/json" -d '{"FAMILY_ADDRESS":"plaintext"}'
				curl -sk --header "X-Vault-Token: "${VAULT_TOKEN} --request POST ${VAULT_URL}/v1/aead-secrets/config -H "Content-Type: application/json" -d '{"address-line1":"FAMILY_ADDRESS"}'
				curl -sk --header "X-Vault-Token: "${VAULT_TOKEN} --request POST ${VAULT_URL}/v1/aead-secrets/config -H "Content-Type: application/json" -d '{"postcode":"FAMILY_ADDRESS"}'

		*/

		Paths: []*framework.Path{
			// aead/info
			&framework.Path{
				Pattern:         "info",
				HelpSynopsis:    "Display information about this plugin",
				HelpDescription: "Displays information about the plugin, such as the plugin version and where to get help.",
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback:                    b.pathInfo,
						ForwardPerformanceStandby:   true,
						ForwardPerformanceSecondary: true,
					},
				},
				// Callbacks: map[logical.Operation]framework.OperationFunc{
				// 	logical.ReadOperation: b.pathInfo,
				// },
			},
			// aead/config
			&framework.Path{
				Pattern:         "config",
				HelpSynopsis:    "Configure aead secret engine.",
				HelpDescription: "Configure aead secret engine.",
				Fields:          map[string]*framework.FieldSchema{}, // commented out as i do not want to define a schema as it is a map and i don't know what the keys will be called
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: b.pathConfigRead,
					},
					logical.UpdateOperation: &framework.PathOperation{
						Callback:                    b.pathConfigWrite,
						ForwardPerformanceStandby:   true,
						ForwardPerformanceSecondary: true,
					},
				},
			},
			// aead/configOverwrite
			&framework.Path{
				Pattern:         "configOverwrite",
				HelpSynopsis:    "Configure aead secret engine.",
				HelpDescription: "Configure aead secret engine.",
				Fields:          map[string]*framework.FieldSchema{}, // commented out as i do not want to define a schema as it is a map and i don't know what the keys will be called
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: b.pathConfigRead,
					},
					logical.UpdateOperation: &framework.PathOperation{
						Callback:                    b.pathConfigOverwrite,
						ForwardPerformanceStandby:   true,
						ForwardPerformanceSecondary: true,
					},
				},
			},
			&framework.Path{
				Pattern:         "configDelete",
				HelpSynopsis:    "Configure aead secret engine.",
				HelpDescription: "Configure aead secret engine.",
				Fields:          map[string]*framework.FieldSchema{}, // commented out as i do not want to define a schema as it is a map and i don't know what the keys will be called
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: b.pathConfigRead,
					},
					logical.UpdateOperation: &framework.PathOperation{
						Callback:                    b.pathConfigDelete,
						ForwardPerformanceStandby:   true,
						ForwardPerformanceSecondary: true,
					},
				},
			},
			// aead/encrypt
			&framework.Path{
				Pattern:         "encrypt",
				HelpSynopsis:    "Encrypt or decrypt data with the aead key held in config",
				HelpDescription: "Encrypt or decrypt data with the aead key held in config",
				Fields: map[string]*framework.FieldSchema{
					"aeadData": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Data to be (d)encrypted",
						Default:     "",
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: b.pathAeadEncrypt,
					},
				},
				// Callbacks: map[logical.Operation]framework.OperationFunc{
				// 	logical.UpdateOperation: b.pathAeadEncrypt,
				// },
			},
			// aead/decrypt
			&framework.Path{
				Pattern:         "decrypt",
				HelpSynopsis:    "Decrypt data with the aead key held in config",
				HelpDescription: "Decrypt data with the aead key held in config.",
				Fields: map[string]*framework.FieldSchema{
					"aeadData": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Data to be decrypted",
						Default:     "",
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: b.pathAeadDecrypt,
					},
				},
				// Callbacks: map[logical.Operation]framework.OperationFunc{
				// 	logical.UpdateOperation: b.pathAeadDecrypt,
				// },
			},
			// aead/rotate
			&framework.Path{
				Pattern:         "rotate",
				HelpSynopsis:    "rotate the keys.",
				HelpDescription: "Rotate the keys.",
				Fields:          map[string]*framework.FieldSchema{}, // commented out as i do not want to define a schema as it is a map and i don't know what the keys will be called
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback:                    b.pathKeyRotate,
						ForwardPerformanceStandby:   true,
						ForwardPerformanceSecondary: true,
					},
				},
			},
			// aead/createAEADkey
			&framework.Path{
				Pattern:         "createAEADkey",
				HelpSynopsis:    "Create AEAD keys",
				HelpDescription: "Create a AEAD key held in config.",
				Fields: map[string]*framework.FieldSchema{
					"aeadData": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Data to be Encrypted",
						Default:     "",
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback:                    b.pathAeadCreateNonDeterministicKeys,
						ForwardPerformanceStandby:   true,
						ForwardPerformanceSecondary: true,
					},
				},
			},
			// aead/createAEADkeyOverwrite
			&framework.Path{
				Pattern:         "createAEADkeyOverwrite",
				HelpSynopsis:    "Create AEAD keys",
				HelpDescription: "Create a AEAD key held in config.",
				Fields: map[string]*framework.FieldSchema{
					"aeadData": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Data to be Encrypted",
						Default:     "",
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback:                    b.pathAeadCreateNonDeterministicKeysOverwrite,
						ForwardPerformanceStandby:   true,
						ForwardPerformanceSecondary: true,
					},
				},
			},
			// aead/createDAEADkey
			&framework.Path{
				Pattern:         "createDAEADkey",
				HelpSynopsis:    "Create DAEAD keys",
				HelpDescription: "Create a DAEAD key held in config.",
				Fields: map[string]*framework.FieldSchema{
					"aeadData": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Data to be Encrypted",
						Default:     "",
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback:                    b.pathAeadCreateDeterministicKeys,
						ForwardPerformanceStandby:   true,
						ForwardPerformanceSecondary: true,
					},
				},
			},
			// aead/createDAEADkey
			&framework.Path{
				Pattern:         "createDAEADkeyOverwrite",
				HelpSynopsis:    "Create DAEAD keys",
				HelpDescription: "Create a DAEAD key held in config.",
				Fields: map[string]*framework.FieldSchema{
					"aeadData": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Data to be Encrypted",
						Default:     "",
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback:                    b.pathAeadCreateDeterministicKeysOverwrite,
						ForwardPerformanceStandby:   true,
						ForwardPerformanceSecondary: true,
					},
				},
			},
			// aead/keytypes
			&framework.Path{
				Pattern:         "keytypes",
				HelpSynopsis:    "Get the key types",
				HelpDescription: "Read the key types.",
				Fields:          map[string]*framework.FieldSchema{},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: b.pathReadKeyTypes,
					},
				},
			},
			// aead/bqsync
			&framework.Path{
				Pattern:         "bqsync",
				HelpSynopsis:    "sync the keys to bq routine.",
				HelpDescription: "sync the keys to bq routine",
				Fields:          map[string]*framework.FieldSchema{}, // commented out as i do not want to define a schema as it is a map and i don't know what the keys will be called
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback:                    b.pathBQKeySync,
						ForwardPerformanceStandby:   true,
						ForwardPerformanceSecondary: true,
					},
				},
			},

			// aead/encryptcol
			&framework.Path{
				Pattern:         "encryptcol",
				HelpSynopsis:    "Encrypt or decrypt data with the aead key held in config",
				HelpDescription: "Encrypt or decrypt data with the aead key held in config",
				Fields: map[string]*framework.FieldSchema{
					"aeadData": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Data to be (d)encrypted",
						Default:     "",
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: b.pathAeadEncryptBulkCol,
					},
				},
			},
			// aead/decryptcol
			&framework.Path{
				Pattern:         "decryptcol",
				HelpSynopsis:    "Decrypt data with the aead key held in config",
				HelpDescription: "Decrypt data with the aead key held in config.",
				Fields: map[string]*framework.FieldSchema{
					"aeadData": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Data to be decrypted",
						Default:     "",
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{
						Callback: b.pathAeadDecryptBulkCol,
					},
				},
			},
			// aead/updateKeyStatus
			&framework.Path{
				Pattern:         "updateKeyStatus",
				HelpSynopsis:    "Update Key Status.",
				HelpDescription: "Update Key Status.",
				Fields:          map[string]*framework.FieldSchema{}, // commented out as i do not want to define a schema as it is a map and i don't know what the keys will be called
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: b.pathConfigRead,
					},
					logical.UpdateOperation: &framework.PathOperation{
						Callback:                    b.pathUpdateKeyStatus,
						ForwardPerformanceStandby:   true,
						ForwardPerformanceSecondary: true,
					},
				},
			},
			// aead/updateKeyMaterial
			&framework.Path{
				Pattern:         "updateKeyMaterial",
				HelpSynopsis:    "Update Key Material.",
				HelpDescription: "Update Key Material.",
				Fields:          map[string]*framework.FieldSchema{}, // commented out as i do not want to define a schema as it is a map and i don't know what the keys will be called
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: b.pathConfigRead,
					},
					logical.UpdateOperation: &framework.PathOperation{
						Callback:                    b.pathUpdateKeyMaterial,
						ForwardPerformanceStandby:   true,
						ForwardPerformanceSecondary: true,
					},
				},
			},
			// aead/updateKeyID
			&framework.Path{
				Pattern:         "updateKeyID",
				HelpSynopsis:    "Update Key ID.",
				HelpDescription: "Update Key ID.",
				Fields:          map[string]*framework.FieldSchema{}, // commented out as i do not want to define a schema as it is a map and i don't know what the keys will be called
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: b.pathConfigRead,
					},
					logical.UpdateOperation: &framework.PathOperation{
						Callback:                    b.pathUpdateKeyID,
						ForwardPerformanceStandby:   true,
						ForwardPerformanceSecondary: true,
					},
				},
			},
			// aead/updatePrimaryKeyID
			&framework.Path{
				Pattern:         "updatePrimaryKeyID",
				HelpSynopsis:    "Update Primary Key ID.",
				HelpDescription: "Update Primary Key ID.",
				Fields:          map[string]*framework.FieldSchema{}, // commented out as i do not want to define a schema as it is a map and i don't know what the keys will be called
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: b.pathConfigRead,
					},
					logical.UpdateOperation: &framework.PathOperation{
						Callback:                    b.pathUpdatePrimaryKeyID,
						ForwardPerformanceStandby:   true,
						ForwardPerformanceSecondary: true,
					},
				},
			},
			// aead/pathImportKey
			&framework.Path{
				Pattern:         "importKey",
				HelpSynopsis:    "Import a key.",
				HelpDescription: "Import a key.",
				Fields:          map[string]*framework.FieldSchema{}, // commented out as i do not want to define a schema as it is a map and i don't know what the keys will be called
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: b.pathConfigRead,
					},
					logical.UpdateOperation: &framework.PathOperation{
						Callback:                    b.pathImportKey,
						ForwardPerformanceStandby:   true,
						ForwardPerformanceSecondary: true,
					},
				},
			},
		},
	}
	return &b
}

const backendHelp = "The aead secrets engine generates aead tokens."

// validateFields verifies that no bad arguments were given to the request.
func validateFields(req *logical.Request, data *framework.FieldData) error {
	var unknownFields []string
	for k := range req.Data {
		if _, ok := data.Schema[k]; !ok {
			unknownFields = append(unknownFields, k)
		}
	}

	if len(unknownFields) > 0 {
		// Sort since this is a human error
		sort.Strings(unknownFields)

		return fmt.Errorf("unknown fields: %q", unknownFields)
	}

	return nil
}
