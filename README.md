# AWS Token Manager

This program is designed to manage AWS SSO (Single Sign-On) profiles and retrieve authentication tokens. It provides functionality for setting up profiles and obtaining tokens for both SSO and Assume SSO profiles.
It uses the `credential_process` field in the `~/.aws/config` file to retrieve the authentication token for the specified profile.

## Why?

Saves you to type `aws sso login ...` every time you need to login to AWS SSO.
On MacOS, you can set it up not to use the default browser.
Logs actions in the ~/.aws/ssologinlite/logs directory.

## Config

config example:
```cat << EOF > ~/.config/ssologinlite.toml
browser = "firefox"
default_sso_url = "https://myawsorg.awsapps.com/start/"
EOF
```

## Features

- Setup AWS SSO profiles
- Retrieve authentication tokens for SSO and Assume SSO profiles

## Installation

To install the program, run the following command:

- Download the binary from the release page
  ```
  curl -LO https://github.com/rowkilian/ssologinlite/releases/download/v0.3.5/ssologinlite.zip
  unzip ssologinlite.zip
  mv ssologinlite /usr/local/bin
  ```

- git
  ```
  git clone
  cd ssologinlite
  cargo install --path .
  ```


## Usage

The program supports two main commands:

1. Setup:
    ```
    ssologinlite setup
    ```
    This command sets up the AWS SSO profiles.
    It will back up the existing ~/.aws/config file and create a new one with the same profile names.
    your ~/.aws/config file should look like this:
    ```
    [default]
    credential_process=/Users/kilian/.cargo/bin/ssologinlite token --profile default
    output=json
    ```

2. Token:
    ```
    ssologinlite token <profile_name>
    ```
    This command retrieves the authentication token for the specified profile.
    Add the `--debug` flag to any command to enable debug logging:
    ```
    ssologinlite -- --debug token <profile_name>
    ```

3. Integrate in starship:
    Add the following configuration to the `~/.config/starship.toml` file:
    ```
    [custom.sso_expiration]
    when = '''ssologinlite sso-expires-soon'''
    command = '''ssologinlite sso-expiration'''
    format = '[\[$output\]]($style) '
    style = 'bold red'
    ```
  This command sets up the starship and show if the sso credentials are expired.

## Note

This program is designed to work with AWS SSO and assumes the existence of a custom `ssologinlite` crate for AWS-related functionality. Ensure you have the necessary AWS credentials and permissions set up before using this program.
