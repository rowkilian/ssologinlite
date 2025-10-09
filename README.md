# ssologinlite

A lightweight AWS SSO (Single Sign-On) authentication manager that automates credential management for AWS CLI and kubectl.

## Why?

- **No manual logins**: Eliminates the need to run `aws sso login` repeatedly
- **Custom browser support**: On macOS, use your preferred browser instead of the default
- **EKS integration**: Generate authentication tokens for Amazon EKS clusters
- **Automatic refresh**: Credentials are cached and refreshed automatically
- **Audit logging**: All actions are logged to `~/.aws/ssologinlite/logs/`

## Configuration

Create a configuration file at `~/.config/ssologinlite.toml`:

```toml
browser = "firefox"
default_sso_url = "https://myawsorg.awsapps.com/start/"
```

**Options:**
- `browser`: Browser to use for SSO login (e.g., "firefox", "chrome", "safari")
- `default_sso_url`: Your organization's AWS SSO start URL

## Features

- **AWS SSO Profile Management**: Automatically configure and manage SSO profiles
- **Assume Role Support**: Seamlessly handle role assumption across accounts
- **EKS Authentication**: Generate kubectl-compatible authentication tokens
- **Credential Caching**: Reduce authentication overhead with intelligent caching
- **Shell Integration**: Starship prompt integration for credential expiration warnings

## Installation

### Option 1: Download Pre-built Binary

```bash
curl -LO https://github.com/rowkilian/ssologinlite/releases/download/v0.3.5/ssologinlite.zip
unzip ssologinlite.zip
mv ssologinlite /usr/local/bin
chmod +x /usr/local/bin/ssologinlite
```

### Option 2: Build from Source

```bash
git clone https://github.com/rowkilian/ssologinlite.git
cd ssologinlite
cargo install --path .
```


## Usage

### Setup AWS Profiles

Configure your AWS SSO profiles to use ssologinlite:

```bash
ssologinlite setup
```

This command:
- Backs up your existing `~/.aws/config` file
- Configures profiles to use ssologinlite as the credential process

Your `~/.aws/config` will be updated to look like:

```ini
[default]
credential_process = /path/to/ssologinlite token --profile default
output = json
```

### Get AWS Credentials

Retrieve authentication tokens for a specific profile:

```bash
ssologinlite token <profile_name>
```

The credentials are cached and automatically refreshed when needed.

### EKS Authentication

Generate authentication tokens for Amazon EKS clusters:

```bash
ssologinlite eks --profile <profile_name> --cluster <cluster_name> --region <aws_region>
```

**Example:**
```bash
ssologinlite eks --profile production --cluster my-eks-cluster --region us-west-2
```

This generates a kubectl-compatible authentication token. Configure kubectl to use it:

```yaml
# ~/.kube/config
users:
- name: my-eks-cluster
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: ssologinlite
      args:
        - eks
        - --profile
        - production
        - --cluster
        - my-eks-cluster
        - --region
        - us-west-2
```

### Debug Mode

Enable detailed logging for troubleshooting:

```bash
ssologinlite --debug token <profile_name>
```

## Shell Integration

### Starship Prompt

Show SSO credential expiration status in your shell prompt by adding to `~/.config/starship.toml`:

```toml
[custom.sso_expiration]
when = '''ssologinlite sso-expires-soon'''
command = '''ssologinlite sso-expiration'''
format = '[\[$output\]]($style) '
style = 'bold red'
```

This displays a warning when your SSO credentials are about to expire.

## Requirements

- AWS SSO must be configured in your organization
- Valid AWS SSO permissions for the profiles you want to use
- For EKS: Appropriate IAM permissions to access EKS clusters

## How It Works

`ssologinlite` integrates with AWS CLI's `credential_process` mechanism:

1. When you run an AWS CLI command, it calls `ssologinlite token`
2. ssologinlite checks for cached, valid credentials
3. If needed, it initiates SSO login via your browser
4. Fresh credentials are cached for future use
5. The credentials are returned to AWS CLI in the expected JSON format

For EKS, it generates pre-signed STS URLs following the AWS authentication protocol, compatible with kubectl's exec credential plugin system.

## License

See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
