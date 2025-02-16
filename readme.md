# SubTack

SubTack is a Go-based tool for detecting possible **subdomain takeovers**.

## Features
- Automatically manages and updates fingerprints from the [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) repository
- Default fingerprint cache at `~/.config/subtack/fingerprints.json`
- Manual update option with `--update`
- Supports:
  - **Concurrency** (`--threads`)
  - **Rate limiting** (`--rate-limit`)
  - **Custom HTTP headers** (`--user-agent`, `--cookies`)
- Reads input from `stdin`, output formatted as:
  ```
  [subtack] domain -> cname (possible takeover)
  ```
- Optional flags:
  - `--fingerprints <path>`: Specify a custom JSON fingerprint file
  - `--silent`: Silent mode (reduces terminal output)

## Installation


- Github
```sh
git clone https://github.com/0xBl4nk/subtack.git
cd subtack
go build -o subtack
```
- Go install
```bash
go install -v github.com/0xBl4nk/subtack@latest
```

## Usage

```sh
cat subdomains.txt | ./subtack --threads 10 --rate-limit 5
```
