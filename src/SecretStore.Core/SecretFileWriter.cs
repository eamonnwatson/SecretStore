using System.Buffers.Text;
using System.Text;
using System.Text.Json;

namespace SecretStore.Core;

// Serialises encrypted secret data to disk in compact JWE format and ensures writes
// are atomic so a crash or power loss mid-write cannot corrupt the store file.
internal static class SecretFileWriter
{
    internal static void Write(string path, byte[] salt, byte[] nonce, byte[] ciphertext, byte[] tag)
    {
        // Build the JWE protected header carrying the algorithm identifiers and PBKDF2 parameters.
        // "alg":"dir" signals direct key agreement — no CEK wrapping occurs.
        // "enc":"A256GCM" identifies AES-256-GCM as the content encryption algorithm.
        // p2s (Base64url-encoded salt) and p2c (iteration count) allow the reader to re-derive
        // the exact same key without any additional state outside this file.
        var header = JsonSerializer.SerializeToUtf8Bytes(new JweHeader
        {
            Alg = "dir",
            Enc = "A256GCM",
            P2s = Base64Url.EncodeToString(salt),
            P2c = 310_000   // Must match SecretEncryptor.Iterations — changing this breaks existing stores.
        }, JweHeaderContext.Default.JweHeader);

        // Assemble the five-segment compact JWE string.
        // Segment [1] (the encrypted CEK) is intentionally empty because direct encryption
        // ("alg":"dir") does not wrap a content-encryption key.
        var jwe = string.Join('.', [
            Base64Url.EncodeToString(header),
            "",
            Base64Url.EncodeToString(nonce),
            Base64Url.EncodeToString(ciphertext),
            Base64Url.EncodeToString(tag)
        ]);

        // Write atomically via temp file + rename.
        // Writing to a .tmp file first and then renaming means the target path always either
        // holds the previous complete file or the new complete file — never a partial write.
        // File.Move with overwrite:true is atomic on most operating systems at the OS level.
        string tmp = path + ".tmp";

        File.WriteAllText(tmp, jwe, Encoding.UTF8);
        File.Move(tmp, path, overwrite: true);
    }
}
