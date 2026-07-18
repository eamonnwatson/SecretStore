using System.Text.Json.Serialization;

namespace SecretStore.Core;

// Represents the protected header of a compact JWE (RFC 7516).
// This header is Base64url-encoded and stored as the first dot-separated segment of the store file.
// It is not encrypted, but its integrity is covered by the AES-GCM authentication tag.
internal sealed class JweHeader
{
    // Key management algorithm. "dir" means direct key agreement:
    // the derived key is used directly as the content-encryption key — no CEK wrapping occurs.
    [JsonPropertyName("alg")]
    public string Alg { get; set; } = default!;

    // Content encryption algorithm. "A256GCM" = AES-256-GCM.
    [JsonPropertyName("enc")]
    public string Enc { get; set; } = default!;

    // PBKDF2 salt, Base64url-encoded (JWE PBES2 parameter p2s — RFC 7518 §4.8.1.1).
    // Stored here so the reader can re-derive the decryption key without any external state.
    [JsonPropertyName("p2s")]
    public string P2s { get; set; } = default!;

    // PBKDF2 iteration count (JWE PBES2 parameter p2c — RFC 7518 §4.8.1.2).
    // Must match the value used during encryption; changing it would break existing store files.
    [JsonPropertyName("p2c")]
    public int P2c { get; set; }
}

// Source-generated serialisation context for JweHeader.
// Required for Native AOT / trim-safe builds where reflection-based JSON serialisation is unavailable.
[JsonSerializable(typeof(JweHeader))]
internal sealed partial class JweHeaderContext : JsonSerializerContext;
