# SecretStore – Copilot Instructions

## Architecture Overview

Two projects in `src/`:

- **`SecretStore.Core`** – class library: encryption, serialization, path navigation, file I/O.
- **`SecretStore.CLI`** – top-level-statements entry point (`Program.cs`) that wraps `SecretStore.Core`.

### Data Flow

```
CLI (Program.cs)
  → SecretStore.Open/Create          (SecretStore.cs)
	→ SecretFileReader.Read           (parses compact JWE from disk)
	→ SecretEncryptor.Decrypt         (PBKDF2-SHA512 + AES-256-GCM)
	→ SecretSerializer.Deserialize    (UTF-8 JSON → JsonNode tree)
  ← in-memory JsonNode root
  → SecretPath.Get/Set/Remove/List   (colon-delimited key navigation)
  → SecretStore.Save
	→ SecretEncryptor.Encrypt
	→ SecretFileWriter.Write          (atomic tmp-file rename)
```

### Storage Format

The store file is a **compact JWE** (5 dot-separated Base64url segments):
`<header>.<empty-cek>.<nonce>.<ciphertext>.<tag>`

The JWE header carries PBKDF2 parameters (`p2s` = salt, `p2c` = 310 000 iterations).

## Secret Paths

Secrets are stored in a nested `JsonObject` tree. Paths use **colon `:` as separator**:

```
aws:prod:access_key_id
database:host
```

All path logic lives in `SecretPath.cs`. Intermediate nodes are auto-created on `Set`.

## Encryption Details (`SecretEncryptor.cs`)

- KDF: PBKDF2-SHA512, 310 000 iterations, 16-byte salt
- Cipher: AES-256-GCM, 12-byte nonce, 16-byte tag
- Keys are allocated on the stack (`stackalloc`) and zeroed with `CryptographicOperations.ZeroMemory` after use.

## CLI Commands & Environment Variables

```
secret init
secret get    <colon:path>
secret set    <colon:path> <value>
secret remove <colon:path>
secret list
secret import <file.json>
secret export
secret save
```

| Variable              | Purpose                                  |
|-----------------------|------------------------------------------|
| `SECRETSTORE_PATH`    | Path to store file (default `~/.secretstore`) |
| `SECRETSTORE_PASSWORD`| Master password (skips interactive prompt) |

## Key Conventions

- **Internal helpers are `internal static`**: `SecretEncryptor`, `SecretPath`, `SecretSerializer`, `SecretFileReader`, `SecretFileWriter` – never expose them publicly.
- **Source-generated JSON**: `SecretStoreJsonContext` (in `Serialization/`) uses `[JsonSerializable]` for AOT-safe serialization of `JweHeader`. Add new serializable types there.
- **Atomic writes**: `SecretFileWriter` always writes to a `.tmp` file then renames to ensure no partial writes corrupt the store.
- **`get` never prints secret values** – it only confirms existence (`[found]` / `[not found]`). Maintain this invariant.
- **`IParsable<T>` generic overload**: `SecretStore.Get<T>` / `TryGet<T>` use `T.Parse`/`T.TryParse` with `CultureInfo.InvariantCulture`. Keep this pattern for any new typed accessors.

## Git Commits

- **Multiple commits are encouraged** — split logically distinct changes into separate commits rather than bundling everything into one.
- **Write in natural language** — commit messages should read like a plain English sentence, not a command or a label.
- **1–2 sentences maximum** — the first sentence describes *what* changed; an optional second sentence explains *why* if it isn't obvious.
- **No prefixes** — do not use conventional-commit prefixes (`feat:`, `fix:`, `chore:`, etc.) or any other tag-style prefix.

Good examples:
```
Added atomic write support to prevent store corruption on interrupted saves.
Removed the legacy base64 helper now that Base64Url is used throughout.
Improved PBKDF2 iteration count to align with current OWASP recommendations.
```

## Build & Run

```powershell
dotnet build
dotnet run --project src/SecretStore.CLI -- init
dotnet run --project src/SecretStore.CLI -- set aws:key myvalue
```
