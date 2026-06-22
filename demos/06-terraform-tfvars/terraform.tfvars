# terraform.tfvars committed alongside main.tf. Practitioners are told to
# gitignore this file, but it frequently lands in the repo with real values.
# NOTE: all values are FAKE placeholders shaped like the real formats.

environment = "prod"
region      = "westus2"

# Azure storage account key would normally sit in this connection string as
# AccountKey=<88-char base64>== — left as a placeholder here so this demo file
# carries no realistic secret literal. (See the test suite for the
# azure_storage_key detector.)
storage_connection_string = "DefaultEndpointsProtocol=https;AccountName=tfstatedemo;AccountKey=__FAKE_AZURE_STORAGE_KEY_PLACEHOLDER__;EndpointSuffix=core.windows.net"

# AWS deployment principal
deploy_access_key_id = "AKIAI44QH8DHBEXAMPLE"

# Azure AD app used by the provider
azure_client_secret = "Abc8Q~deFGhiJKlmNopQRstuVWXyz0123456789_-"

instance_count = 3
