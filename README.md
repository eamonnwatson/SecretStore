# SecretStore

A lightweight, encrypted secret manager for the command line. Secrets are stored in a single encrypted file on disk using AES-256-GCM with a PBKDF2-derived key — no daemons, no cloud, no dependencies.

## Features

- AES-256-GCM encryption with PBKDF2-SHA512 key derivation (310 000 iterations)
- Hierarchical secrets addressed by colon-delimited paths (`aws:prod:access_key_id`)
- Compact [JWE](https://www.rfc-editor.org/rfc/rfc7516) storage format — a single portable file
- AOT-compiled native binary via `PublishAot` — fast startup, no .NET runtime required at runtime
- Atomic writes (temp-file rename) to prevent store corruption
- `SecretStore.Core` class library for embedding secret access in your own .NET apps

## Requirements

- [.NET 10 SDK](https://dotnet.microsoft.com/download) (build only; published binary is self-contained)

## Installation

### Build & publish a native binary

```powershell
dotnet publish src/SecretStore.CLI -c Release -r win-x64 -o ./publish
```

Replace `win-x64` with your target RID (e.g. `linux-x64`, `osx-arm64`).  
Add the `publish/` directory to your `PATH` so the `secret` command is available everywhere.

### Run without installing

```powershell
dotnet run --project src/SecretStore.CLI -- <command> [args]
```

## Quick Start

```powershell
# Create a new encrypted store (prompts for a master password)
secret init

# Store a secret
secret set aws:prod:access_key_id AKIAIOSFODNN7EXAMPLE

# Confirm a secret exists (value is never printed)
secret get aws:prod:access_key_id
# [found] aws:prod:access_key_id

# List all stored paths
secret list

# Remove a secret
secret remove aws:prod:access_key_id
```

## Commands

| Command | Description |
|---|---|
| `secret init` | Create a new encrypted store |
| `secret get <path>` | Confirm a secret exists (`[found]` / `[not found]`) |
| `secret set <path> <value>` | Store or update a secret |
| `secret remove <path>` | Delete a secret |
| `secret list` | List all secret paths |
| `secret import <file.json>` | Replace the store contents from a plaintext JSON file |
| `secret export` | Print the decrypted store as JSON |
| `secret save` | Explicitly flush the in-memory store to disk |

> **Note:** `get` intentionally never prints the secret value — it only confirms existence.

## Environment Variables

| Variable | Description |
|---|---|
| `SECRETSTORE_PATH` | Path to the store file (default: `~/.secretstore`) |
| `SECRETSTORE_PASSWORD` | Master password — skips the interactive prompt |

Setting `SECRETSTORE_PASSWORD` is useful in CI/CD pipelines:

```powershell
$env:SECRETSTORE_PASSWORD = "hunter2"
secret get database:host
```

## Secret Paths

Secrets are organised in a nested tree. Use `:` to separate levels:

```
aws:prod:access_key_id
aws:prod:secret_access_key
database:host
database:port
```

Intermediate nodes are created automatically on `set`.

## Storage Format

The store file is a single-line compact JWE with five Base64url segments:

```
<header>.<empty-cek>.<nonce>.<ciphertext>.<tag>
```

The header carries the PBKDF2 salt (`p2s`) and iteration count (`p2c`), so the file is fully self-contained. Example header (decoded):

```json
{"alg":"dir","enc":"A256GCM","p2s":"<base64url-salt>","p2c":310000}
```

## Using `SecretStore.Core` in Your Own App

Add a project reference to `src/SecretStore.Core` and use the `SecretStore` class directly:

```csharp
// Open an existing store
var store = SecretStore.Core.SecretStore.Open("/path/to/.secretstore", masterPassword);

// Read a secret
string? value = store.Get("database:host");

// Read a typed secret (uses IParsable<T>)
int port = store.Get<int>("database:port");

// Write and persist
store.Set("database:host", "localhost");
store.Save();
```

## Building

```powershell
dotnet build
```

## Project Structure

```
src/
  SecretStore.Core/   # Class library — encryption, serialization, path navigation, I/O
  SecretStore.CLI/    # Top-level-statements CLI entry point (publishes as 'secret')
```

## Security Notes

- Encryption keys are derived per-save with a fresh random salt and nonce.
- Key material is stack-allocated and zeroed with `CryptographicOperations.ZeroMemory` immediately after use.
- A wrong password throws `CryptographicException` (authentication tag mismatch) rather than producing garbage output.
- The master password is read from the terminal with echo suppressed; use `SECRETSTORE_PASSWORD` only in trusted environments.

## License

MIT
