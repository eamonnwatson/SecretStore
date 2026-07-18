using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.Json.Nodes;

namespace SecretStore.Core;

public sealed class SecretStore
{
    private readonly string path;
    private readonly string password;
    private JsonNode root;

    private SecretStore(string path, string password, JsonNode root)
    {
        this.path = path;
        this.password = password;
        this.root = root;
    }
    public static SecretStore Open(string path, string masterPassword)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(masterPassword);

        var data = SecretFileReader.Read(path);
        var plaintext = SecretEncryptor.Decrypt(masterPassword, data.Salt, data.Nonce, data.Ciphertext, data.Tag);
        var root = SecretSerializer.Deserialize(plaintext);

        return new SecretStore(path, masterPassword, root);
    }

    public static SecretStore Create(string path, string masterPassword)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(masterPassword);

        return new SecretStore(path, masterPassword, new JsonObject());
    }

    public string? Get(string path) => SecretPath.Get(root, path);

    public T Get<T>(string path) where T : IParsable<T>
    {
        var raw = Get(path) ?? throw new KeyNotFoundException($"Secret '{path}' not found.");
        return T.Parse(raw, CultureInfo.InvariantCulture);
    }
    public bool TryGet<T>(string path, [NotNullWhen(true)] out T? value) where T : IParsable<T>
    {
        value = default;
        var raw = Get(path);
        if (raw is null)
            return false;
        return T.TryParse(raw, CultureInfo.InvariantCulture, out value);
    }

    public void Set(string path, string value) => SecretPath.Set(root, path, value);

    public bool Remove(string path) => SecretPath.Remove(root, path);

    public bool Exists(string path) => SecretPath.Exists(root, path);

    public IEnumerable<string> List() => SecretPath.List(root);

    public void Save()
    {
        var plaintext = SecretSerializer.Serialize(root);

        SecretEncryptor.Encrypt(plaintext, password, out byte[] salt, out byte[] nonce, out byte[] ciphertext, out byte[] tag);

        var dir = Path.GetDirectoryName(path);

        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        SecretFileWriter.Write(path, salt, nonce, ciphertext, tag);
    }

    public string ExportJson() => SecretSerializer.ExportJson(root);

    public void ImportJson(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        root = SecretSerializer.DeserializeJson(json);
    }
}
