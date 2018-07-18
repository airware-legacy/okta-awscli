# okta_awscli - Retrieve AWS credentials from Okta

Authenticates a user against Okta and then uses the resulting SAML assertion to retrieve temporary STS credentials from AWS.


## Installation

- `virtualenv oktaawscli`
- `source ./oktaawscli/bin/activate`
- `pip install git+ssh://git@github.com/airware/okta-awscli.git@develop`
- Configure okta-awscli via the `~/.okta-aws` file with the following parameters:

```
[default]
base-url = airware.okta.com

## The remaining parameters are optional.
## You will be prompted for them, if they're not included here.
username = <your_okta_username>
password = <your_okta_password> # Only save your password if you know what you are doing!
factor = <your_preferred_mfa_factor> # Current choices are: GOOGLE or OKTA
```

## Usage

`okta-awscli --profile <aws_profile> <awscli action> <awscli arguments>`
- Follow the prompts to enter MFA information (if required) and choose your AWS app and IAM role.
- Subsequent executions will first check if the STS credentials are still valid and skip Okta authentication if so.
- Multiple Okta profiles are supported, but if none are specified, then `default` will be used.


### Example

`okta-awscli --profile my-aws-account iam list-users`

If no awscli commands are provided, then okta-awscli will simply output STS credentials to your credentials file, or console, depending on how `--profile` is set.

Optional flags:
- `--profile` Sets your temporary credentials to a profile in `.aws/credentials`. If omitted, credentials will output to console.
- `--force` Ignores result of STS credentials validation and gets new credentials from AWS. Used in conjunction with `--profile`.
- `--verbose` More verbose output.
- `--debug` Very verbose output. Useful for debugging.
- `--cache` Cache the acquired credentials to ~/.okta-credentials.cache (only if --profile is unspecified)
- `--okta-profile` Use a Okta profile, other than `default` in `.okta-aws`. Useful for multiple Okta tenants.
- `--token` or `-t` Pass in the TOTP token from your authenticator
