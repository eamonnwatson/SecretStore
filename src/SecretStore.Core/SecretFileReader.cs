using System.Buffers.Text;
using System.Text;
using System.Text.Json;

namespace SecretStore.Core;

// Parses a compact JWE serialisation from disk into a SecretFileData value that the
// encryption layer can consume. This class owns the file format contract: exactly 5
// dot-separated Base64url segments as defined by RFC 7516 §3.1.
internal static class SecretFileReader
{
    internal static SecretFileData Read(string path)
    {
        // Trim whitespace to tolerate files that were created on systems with different
        // line endings or were accidentally edited to include a trailing newline.
        var jwe = File.ReadAllText(path, Encoding.UTF8).Trim();
        var parts = jwe.Split('.');

        // The compact JWE format mandates exactly five dot-separated segments:
        //   [0] Base64url(header JSON)
        //   [1] Base64url(encrypted CEK) — always empty for direct encryption ("alg":"dir")
        //   [2] Base64url(nonce / IV)
        //   [3] Base64url(ciphertext)
        //   [4] Base64url(authentication tag)
        if (parts.Length != 5)
            throw new InvalidDataException("Not a valid JWE compact serialization (expected 5 parts).");

        // Decode and deserialise the protected header to extract the PBKDF2 salt (p2s).
        // The header is not encrypted — it carries only the algorithm parameters needed
        // to derive the decryption key, and is authenticated by the GCM tag.
        var headerJson = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[0]));
        var header = JsonSerializer.Deserialize(headerJson, JweHeaderContext.Default.JweHeader)
            ?? throw new InvalidDataException("JWE header could not be deserialized.");

        if (string.IsNullOrEmpty(header.P2s))
            throw new InvalidDataException("JWE header missing 'p2s' (salt).");

        // Extract the cryptographic material from the remaining JWE segments.
        // The salt lives in the header (p2s field) rather than segment [1] because
        // this implementation uses direct key agreement — there is no wrapped CEK.
        var salt = Base64Url.DecodeFromChars(header.P2s);
        var nonce = Base64Url.DecodeFromChars(parts[2]);
        var ciphertext = Base64Url.DecodeFromChars(parts[3]);
        var tag = Base64Url.DecodeFromChars(parts[4]);

        return new SecretFileData(salt, nonce, ciphertext, tag);
    }
}
