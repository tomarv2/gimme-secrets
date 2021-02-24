<p align="center">
    <a href="https://www.apache.org/licenses/LICENSE-2.0" alt="GitHub tag">
        <img src="https://img.shields.io/github/license/tomarv2/terraform-azure-role-assignment" /></a>
    <a href="https://github.com/tomarv2/terraform-azure-role-assignment/tags" alt="GitHub tag">
        <img src="https://img.shields.io/github/v/tag/tomarv2/terraform-azure-role-assignment" /></a>
    <a href="https://github.com/tomarv2/terraform-azure-role-assignment/pulse" alt="Activity">
        <img src="https://img.shields.io/github/commit-activity/m/tomarv2/terraform-azure-role-assignment" /></a>
    <a href="https://stackoverflow.com/users/6679867/tomarv2" alt="Stack Exchange reputation">
        <img src="https://img.shields.io/stackexchange/stackoverflow/r/6679867"></a>
    <a href="https://discord.gg/XH975bzN" alt="chat on Discord">
        <img src="https://img.shields.io/discord/813961944443912223?logo=discord"></a>
    <a href="https://twitter.com/intent/follow?screen_name=varuntomar2019" alt="follow on Twitter">
        <img src="https://img.shields.io/twitter/follow/varuntomar2019?style=social&logo=twitter"></a>
</p>

# gimme-secrets

gimme-secrets is a cli tool to manage AWS Parameter Store values.

It can:
- Put entry in Parameter Store
- Get value from Parameter Store
- Decrypt and Encrypt value using KMS
- Move Parameter Store entries between AWS accounts and regions.


## Prerequisites
Python 3.6 or above

## Configuration

For AWS set the `AWS_MASTER_ROLE_ARN` to the ARN of the account which has permissions to switch to other accounts.


### How to use?

Install/Upgrade from PyPi:

`pip3 install --upgrade gimme-secrets`

- run `gimme-secrets` for available options

```
gimme-secrets
Usage: gimme-secrets [OPTIONS] COMMAND [ARGS]...

  Command-line interface for managing secrets for:

   AWS

Options:
  --help  Show this message and exit.

Commands:
  aws-decrypt-secret  aws decrypt secrets using kms key
  aws-encrypt-secret  aws encrypt secrets using kms key
  aws-get-secret      aws get values from Parameter Store
  aws-put-secret      aws put values in Parameter Store
  copy-secret         copy values from one account or region to another

```
