package vault

import (
	"context"
	"log"
	"os"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

const (
	envVaultAddr      = "VAULT_ADDR"
	provider          = "vault"
	resInit           = provider + "_init"
	resUnseal         = provider + "_unseal"
	argVaultAddr      = "vault_addr"
	argRequestHeaders = "request_headers"
)

func init() {
	schema.DescriptionKind = schema.StringMarkdown
}

func New(version string) func() *schema.Provider {
	return func() *schema.Provider {
		p := &schema.Provider{
			Schema: providerSchema(),
			ResourcesMap: map[string]*schema.Resource{
				resInit:   resourceInit(),
				resUnseal: resourceUnseal(),
			},
			DataSourcesMap: map[string]*schema.Resource{
				resInit:   providerDatasourceInit(),
				resUnseal: providerDatasourceSeal(),
			},
		}

		p.ConfigureContextFunc = configure(version, p)

		return p
	}
}

type apiClient struct {
	client *api.Client
	url    string
}

func providerSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		argVaultAddr: {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Vault instance URL",
		},
		argRequestHeaders: {
			Type:     schema.TypeMap,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
	}
}

func configure(version string, p *schema.Provider) func(context.Context, *schema.ResourceData) (interface{}, diag.Diagnostics) {
	return func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		a := &apiClient{}
		if u := d.Get(argVaultAddr).(string); u != "" {
			a.url = u
		} else {
			a.url = os.Getenv(envVaultAddr)
		}

		if a.url == "" {
			return nil, diag.Errorf("argument '%s' is required, or set VAULT_ADDR environment variable", argVaultAddr)
		}

		if c, err := api.NewClient(&api.Config{Address: a.url}); err != nil {
			logError("failed to create Vault API client: %v", err)
			return nil, diag.FromErr(err)
		} else {
			a.client = c
		}

		return a, nil
	}
}

func logError(fmt string, v ...interface{}) {
	log.Printf("[ERROR] "+fmt, v)
}

func logInfo(fmt string, v ...interface{}) {
	log.Printf("[INFO] "+fmt, v)
}

func logDebug(fmt string, v ...interface{}) {
	log.Printf("[DEBUG] "+fmt, v)
}
