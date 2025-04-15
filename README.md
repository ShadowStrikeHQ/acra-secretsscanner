# acra-SecretsScanner
A command-line tool that scans source code files for exposed secrets like API keys, passwords, and private keys.  Uses regular expressions and entropy analysis to identify potential secrets. - Focused on Performs static code analysis on Python code to identify potential security vulnerabilities (e.g., insecure string formatting, hardcoded credentials, code complexity). Generates reports highlighting areas that require further review by security engineers.

## Install
`git clone https://github.com/ShadowStrikeHQ/acra-secretsscanner`

## Usage
`./acra-secretsscanner [params]`

## Parameters
- `-h`: Show help message and exit
- `-o`: Path to the file to save the scan results.

## License
Copyright (c) ShadowStrikeHQ
