package vault

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const (
	argSealed = "sealed"
)

func providerDatasourceSeal() *schema.Resource {
	return &schema.Resource{
		// This description is used by the documentation generator and the language server.
		Description: "Resource for vault operator init",

		ReadContext: providerDatasourceReadSeal,

		Schema: map[string]*schema.Schema{
			argSealed: {
				Description: "The current seal state of Vault.",
				Type:        schema.TypeBool,
				Computed:    true,
			},
		},
	}
}

func providerDatasourceReadSeal(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	client := meta.(*apiClient)

	d.SetId("seal_status")

	res, err := client.client.Sys().SealStatus()
	if err != nil {
		logError("failed to read seal status from Vault: %v", err)
		return diag.FromErr(err)
	}

	logDebug("response: %v", res)

	if err := d.Set(argSealed, res); err != nil {
		return diag.FromErr(err)
	}

	return diag.Diagnostics{}
}
