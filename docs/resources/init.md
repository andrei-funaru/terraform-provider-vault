---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "Resource: vault_init"
subcategory: ""
description: |-
  Resource for vault init
---

# vault_init (Resource)

Resource for vault init

## Example Usage

```terraform
resource "vault_init" "simple" {
  secret_shares    = 5
  secret_threshold = 3
}
```

```terraform
locals {
  pgp_public_key      = sensitive(filebase64("~/.gnupg/public.asc"))
  pgp_root_public_key = sensitive(filebase64("~/.gnupg/public_root.asc"))
}

resource "vault_init" "pgp" {
  secret_shares    = 5
  secret_threshold = 3
  pgp_keys = [local.pgp_public_key, local.pgp_public_key, local.pgp_public_key, local.pgp_public_key, local.pgp_public_key]
  root_token_pgp_key = local.pgp_root_public_key
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

### Optional
- **secret_shares** (Number) Specifies the number of shares to split the master key into.
  - `Default: 5`
- **secret_threshold** (Number) Specifies the number of shares required to reconstruct the master key.
  - `Default: 3`
- **id** (String) The ID of this resource.
- **recovery_shares** (Number) Specifies the number of shares to split the recovery key into.
- **recovery_threshold** (Number) Specifies the number of shares required to reconstruct the recovery key.
- **pgp_keys** (List of String) Specifies an array of PGP public keys used to encrypt the output unseal keys. Ordering is preserved. The keys must be base64-encoded from their original binary representation. The size of this array must be the same as **secret_shares**.
- **recovery_pgp_keys** (List of String) Specifies an array of PGP public keys used to encrypt the output recovery keys. Ordering is preserved. The keys must be base64-encoded from their original binary representation. The size of this array must be the same as **recovery_shares**. This is only available when using Auto Unseal.
- **root_token_pgp_key** (String) Specifies a PGP public key used to encrypt the initial root token. The key must be base64-encoded from its original binary representation.

### Read-Only

- **keys** (List of String, Sensitive) The unseal keys. If **pgp_keys** was provided, each unseal key will be encrypted using the corresponding PGP key.
- **keys_base64** (List of String, Sensitive) The unseal keys, base64 encoded.
- **recovery_keys** (List of String, Sensitive) The recovery keys. If **recovery_pgp_keys** was provided, each recovery key will be encrypted using the corresponding recovery PGP key.
- **recovery_keys_base64** (List of String, Sensitive) The recovery keys, base64 encoded.
- **root_token** (String, Sensitive) The Vault Root Token. If **root_token_pgp_key** was provided, it will be encrypted with it and base64 encoded.
