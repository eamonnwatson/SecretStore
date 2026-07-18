using System.Buffers.Text;
using System.Text;
using System.Text.Json;

namespace SecretStore.Core;

internal static class SecretFileReader
{
    internal static SecretFileData Read(string path)
    {
        var jwe = File.ReadAllText(path, Encoding.UTF8).Trim();
        var parts = jwe.Split('.');

        if (parts.Length != 5)
            throw new InvalidDataException("Not a valid JWE compact serialization (expected 5 parts).");

        var headerJson = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[0]));
        var header = JsonSerializer.Deserialize(headerJson, JweHeaderContext.Default.JweHeader)
            ?? throw new InvalidDataException("JWE header could not be deserialized.");

        if (string.IsNullOrEmpty(header.P2s))
            throw new InvalidDataException("JWE header missing 'p2s' (salt).");

        var salt = Base64Url.DecodeFromChars(header.P2s);
        var nonce = Base64Url.DecodeFromChars(parts[2]);
        var ciphertext = Base64Url.DecodeFromChars(parts[3]);
        var tag = Base64Url.DecodeFromChars(parts[4]);

        return new SecretFileData(salt, nonce, ciphertext, tag);
    }
}
