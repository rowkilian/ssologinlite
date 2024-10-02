# AWS Token Manager

This Rust program is designed to manage AWS SSO (Single Sign-On) profiles and retrieve authentication tokens. It provides functionality for setting up profiles and obtaining tokens for both SSO and Assume SSO profiles.

## Features

- Setup AWS SSO profiles
- Retrieve authentication tokens for SSO and Assume SSO profiles
- Debug mode for detailed logging
- Command-line interface using `clap`

## Dependencies

This program relies on the following main crates:
- `anyhow` for error handling
- `ssologinlite` (custom crate) for AWS profile management
- `clap` for parsing command-line arguments
- `log` for logging
- `tokio` for asynchronous runtime

## Usage

The program supports two main commands:

1. Setup:
   ```
   cargo run -- setup
   ```
   This command sets up the AWS SSO profiles.

2. Token:
   ```
   cargo run -- token <profile_name>
   ```
   This command retrieves the authentication token for the specified profile.

Add the `--debug` flag to any command to enable debug logging:
```
cargo run -- --debug token <profile_name>
```

## Error Handling

The program uses `anyhow` for error handling and defines a custom error type `MyErrors` for specific error cases.

## Structure

- `main()`: The entry point of the program. It parses CLI arguments and executes the appropriate command.
- `Cli`: A struct defined using `clap` to parse command-line arguments.
- `Commands`: An enum representing the available commands (Setup and Token).
- `Profiles`: A custom type from the `ssologinlite` crate that manages AWS profiles.
- `MyErrors`: A custom error enum for specific error cases.

## Note

This program is designed to work with AWS SSO and assumes the existence of a custom `ssologinlite` crate for AWS-related functionality. Ensure you have the necessary AWS credentials and permissions set up before using this program.
