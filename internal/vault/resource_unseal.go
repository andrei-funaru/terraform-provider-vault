package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/openpgp"
	"gonum.org/v1/gonum/stat/combin"
)

const (
	argSecretShares    = "secret_shares"
	argSecretThreshold = "secret_threshold"
	argKeys            = "keys"
	argPGPKeys         = "pgp_keys"
	argpassphrase      = "passphrase"
)

func resourceUnseal() *schema.Resource {
	return &schema.Resource{
		// This description is used by the documentation generator and the language server.
		Description: "Resource for vault operator unseal",

		CreateContext: resourceUnsealCreate,
		ReadContext:   resourceUnsealRead,
		UpdateContext: resourceUnsealUpdate,
		DeleteContext: resourceUnsealDelete,
		Schema: map[string]*schema.Schema{
			argSecretShares: {
				Description: "Specifies the number of shares the master key was split  into.",
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     5,
			},
			argSecretThreshold: {
				Description: "Specifies the number of shares required to reconstruct the master key.",
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     3,
			},
			argKeys: {
				Description: "The unseal keys.",
				Type:        schema.TypeList,
				Required:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			argPGPKeys: {
				Description: "Specifies an array of PGP public keys used to decript the unseal keys. Ordering is preserved. The keys must be base64-encoded from their original binary representation. The size of this array must be the same as secret_shares.",
				Type:        schema.TypeList,
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			argpassphrase: {
				Description: "Specifies an array of PGP public keys passphrase used to decript the unseal keys. Ordering is preserved. The keys must be base64-encoded from their original binary representation. The size of this array must be the same as secret_shares.",
				Type:        schema.TypeList,
				Optional:    true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func resourceUnsealCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	// use the meta value to retrieve your client from the provider configure method
	client := meta.(*apiClient)

	secretShares := d.Get(argSecretShares).(int)
	secretThreshold := d.Get(argSecretThreshold).(int)
	Keys := d.Get(argKeys).([]interface{})
	pgpKeys := d.Get(argPGPKeys).([]interface{})
	passphrase := d.Get(argpassphrase).([]interface{})

	pgpKeysList := make([]string, len(pgpKeys))
	for i, pgpKey := range pgpKeys {
		pgpKeysList[i] = pgpKey.(string)
	}

	KeysList := make([]string, len(Keys))
	for i, key := range Keys {
		if len(pgpKeys) != 0 {
			decripted_key, err := get_decrypted_key(pgpKeys[i].(string), passphrase[i].(string), key.(string))
			if err != nil {
				logError("failed to unseal Vault: %v", err)
				return diag.FromErr(err)
			}
			KeysList[i] = decripted_key
		} else {
			KeysList[i] = key.(string)
		}
	}
	array := get_index_for_keys(secretShares, secretThreshold)

	for i := 0; i < len(array); i++ {
		res, err := client.client.Sys().Unseal(KeysList[array[i]])
		if err != nil {
			logError("failed to unseal Vault: %v", err)
			return diag.FromErr(err)
		}

		logDebug("response: %v", res)
	}
	if err := updateStateUnseal(d, "create_unseal"); err != nil {
		logError("failed to update state: %v", err)
		return diag.FromErr(err)
	}
	return diag.Diagnostics{}
}

func resourceUnsealRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return diag.Diagnostics{}
}

func resourceUnsealUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return diag.Diagnostics{}
}

func resourceUnsealDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	return diag.Diagnostics{}
}

func updateStateUnseal(d *schema.ResourceData, id string) error {
	d.SetId(id)
	return nil
}

func get_index_for_keys(shares int, threshold int) []int {
	rand.Seed(time.Now().UnixNano())
	combos := combin.Combinations(shares, threshold)
	number := rand.Intn(len(combos))
	fmt.Println(combos[number])
	result := combos[number]
	return result
}

func get_decrypted_key(private_key_path string, passphrase string, encString string) (string, error) {

	// init some vars
	var entity *openpgp.Entity
	var entityList openpgp.EntityList

	// Open the private key file
	keyringFileBuffer, err := os.Open(private_key_path)
	if err != nil {
		return "", err
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}
	entity = entityList[0]

	// Get the passphrase and read the private key.
	// Have not touched the encrypted string yet
	passphraseByte := []byte(passphrase)
	entity.PrivateKey.Decrypt(passphraseByte)

	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	// Decode the base64 string
	dec, err := base64.StdEncoding.DecodeString(encString)
	if err != nil {
		return "", err
	}

	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entityList, nil, nil)
	if err != nil {
		return "", err
	}
	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	decStr := string(bytes)

	return decStr, nil
}
