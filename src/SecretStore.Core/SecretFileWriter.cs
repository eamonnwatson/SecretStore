using System.Buffers.Text;
using System.Text;
using System.Text.Json;

namespace SecretStore.Core;

internal static class SecretFileWriter
{
    internal static void Write(string path, byte[] salt, byte[] nonce, byte[] ciphertext, byte[] tag)
    {
        var header = JsonSerializer.SerializeToUtf8Bytes(new JweHeader
        {
            Alg = "dir",
            Enc = "A256GCM",
            P2s = Base64Url.EncodeToString(salt),
            P2c = 310_000
        }, JweHeaderContext.Default.JweHeader);

        var jwe = string.Join('.', [
            Base64Url.EncodeToString(header),
            "",
            Base64Url.EncodeToString(nonce),
            Base64Url.EncodeToString(ciphertext),
            Base64Url.EncodeToString(tag)
        ]);

        // Write atomically via temp file + rename
        string tmp = path + ".tmp";
        
        File.WriteAllText(tmp, jwe, Encoding.UTF8);
        File.Move(tmp, path, overwrite: true);
    }
}
