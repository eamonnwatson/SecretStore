using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.Json.Nodes;

namespace SecretStore.Core;

/// <summary>
/// Provides a high-level API for creating, opening, and manipulating an encrypted secret store.
/// </summary>
/// <remarks>
/// Secrets are persisted as an AES-256-GCM encrypted JSON object in a compact JWE file on disk.
/// The in-memory representation is a <see cref="JsonNode"/> tree. All navigation uses
/// colon-delimited paths (e.g. <c>aws:prod:access_key_id</c>).
/// <para>
/// The master password is never stored; it is used only to derive the encryption key via
/// PBKDF2-SHA512 at open/save time. A fresh salt and nonce are generated on every <see cref="Save"/>,
/// so two saves of identical content produce different ciphertext.
/// </para>
/// </remarks>
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

    /// <summary>
    /// Opens an existing encrypted secret store from disk and decrypts it into memory.
    /// </summary>
    /// <param name="path">Absolute or relative path to the store file.</param>
    /// <param name="masterPassword">The master password used to derive the decryption key.</param>
    /// <returns>A fully loaded <see cref="SecretStore"/> instance ready for querying.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="path"/> or <paramref name="masterPassword"/> is null or whitespace.
    /// </exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// Thrown when authentication fails, indicating either a wrong password or a corrupted store file.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Thrown when the file is present but does not conform to the expected compact JWE format.
    /// </exception>
    public static SecretStore Open(string path, string masterPassword)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(masterPassword);

        var data = SecretFileReader.Read(path);
        var plaintext = SecretEncryptor.Decrypt(masterPassword, data.Salt, data.Nonce, data.Ciphertext, data.Tag);
        var root = SecretSerializer.Deserialize(plaintext);

        return new SecretStore(path, masterPassword, root);
    }

    /// <summary>
    /// Creates a new, empty secret store associated with the given path and master password.
    /// </summary>
    /// <remarks>
    /// This method does not write anything to disk. Call <see cref="Save"/> to persist the
    /// newly created (empty) store. This separation allows callers to set initial secrets
    /// before the first write.
    /// </remarks>
    /// <param name="path">Absolute or relative path where the store file will be written.</param>
    /// <param name="masterPassword">The master password that will protect this store.</param>
    /// <returns>An empty <see cref="SecretStore"/> instance backed by the given path.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="path"/> or <paramref name="masterPassword"/> is null or whitespace.
    /// </exception>
    public static SecretStore Create(string path, string masterPassword)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(masterPassword);

        return new SecretStore(path, masterPassword, new JsonObject());
    }

    /// <summary>
    /// Retrieves the raw string value at the given colon-delimited path.
    /// </summary>
    /// <param name="path">
    /// A colon-delimited key path such as <c>aws:prod:access_key_id</c>.
    /// </param>
    /// <returns>
    /// The stored string value, or <see langword="null"/> if the path does not exist
    /// or resolves to an intermediate object rather than a leaf value.
    /// </returns>
    public string? Get(string path) => SecretPath.Get(root, path);

    /// <summary>
    /// Retrieves the value at the given path and parses it to <typeparamref name="T"/>.
    /// </summary>
    /// <remarks>
    /// Parsing is always performed with <see cref="CultureInfo.InvariantCulture"/> to ensure
    /// consistent behaviour regardless of the host system's regional settings.
    /// </remarks>
    /// <typeparam name="T">
    /// Any type that implements <see cref="IParsable{T}"/>, e.g. <see cref="int"/>, <see cref="Guid"/>, <see cref="Uri"/>.
    /// </typeparam>
    /// <param name="path">A colon-delimited key path.</param>
    /// <returns>The parsed value of type <typeparamref name="T"/>.</returns>
    /// <exception cref="KeyNotFoundException">Thrown when no secret exists at <paramref name="path"/>.</exception>
    /// <exception cref="FormatException">Thrown when the stored value cannot be parsed as <typeparamref name="T"/>.</exception>
    public T Get<T>(string path) where T : IParsable<T>
    {
        var raw = Get(path) ?? throw new KeyNotFoundException($"Secret '{path}' not found.");
        return T.Parse(raw, CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Attempts to retrieve and parse the value at the given path without throwing on failure.
    /// </summary>
    /// <remarks>
    /// Parsing uses <see cref="CultureInfo.InvariantCulture"/>. Returns <see langword="false"/> both
    /// when the path is absent and when the stored string cannot be parsed as <typeparamref name="T"/>.
    /// </remarks>
    /// <typeparam name="T">Any type that implements <see cref="IParsable{T}"/>.</typeparam>
    /// <param name="path">A colon-delimited key path.</param>
    /// <param name="value">
    /// When this method returns <see langword="true"/>, contains the parsed value;
    /// otherwise <see langword="default"/>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the path exists and the value was parsed successfully;
    /// otherwise <see langword="false"/>.
    /// </returns>
    public bool TryGet<T>(string path, [NotNullWhen(true)] out T? value) where T : IParsable<T>
    {
        value = default;
        var raw = Get(path);
        if (raw is null)
            return false;
        return T.TryParse(raw, CultureInfo.InvariantCulture, out value);
    }

    /// <summary>
    /// Stores or overwrites a secret at the given colon-delimited path.
    /// </summary>
    /// <remarks>
    /// Intermediate nodes in the path are created automatically as <c>JsonObject</c> instances.
    /// Changes are held in memory until <see cref="Save"/> is called.
    /// </remarks>
    /// <param name="path">A colon-delimited key path such as <c>database:host</c>.</param>
    /// <param name="value">The plaintext secret value to store.</param>
    public void Set(string path, string value) => SecretPath.Set(root, path, value);

    /// <summary>
    /// Removes the secret at the given colon-delimited path.
    /// </summary>
    /// <remarks>
    /// Only the leaf key is removed; intermediate parent nodes are left intact.
    /// Call <see cref="Save"/> to persist the deletion.
    /// </remarks>
    /// <param name="path">A colon-delimited key path.</param>
    /// <returns>
    /// <see langword="true"/> if the key was found and removed; <see langword="false"/> if it did not exist.
    /// </returns>
    public bool Remove(string path) => SecretPath.Remove(root, path);

    /// <summary>
    /// Determines whether a secret (or an intermediate namespace node) exists at the given path.
    /// </summary>
    /// <param name="path">A colon-delimited key path.</param>
    /// <returns>
    /// <see langword="true"/> if the path resolves to any node (leaf or object); otherwise <see langword="false"/>.
    /// </returns>
    public bool Exists(string path) => SecretPath.Exists(root, path);

    /// <summary>
    /// Enumerates all leaf secret paths currently held in memory.
    /// </summary>
    /// <returns>
    /// A sequence of fully qualified colon-delimited paths, e.g. <c>aws:prod:access_key_id</c>.
    /// Intermediate namespace nodes are not included — only leaf values are returned.
    /// </returns>
    public IEnumerable<string> List() => SecretPath.List(root);

    /// <summary>
    /// Serializes and encrypts the in-memory secret tree, then writes it atomically to disk.
    /// </summary>
    /// <remarks>
    /// A fresh salt and nonce are generated on every save, so repeated saves of unchanged content
    /// will produce different ciphertext — this is by design to prevent ciphertext comparison attacks.
    /// The parent directory is created if it does not already exist.
    /// The write is atomic: the data is first written to a <c>.tmp</c> file and then renamed over
    /// the target path to avoid partial-write corruption.
    /// </remarks>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// Thrown if encryption fails unexpectedly.
    /// </exception>
    /// <exception cref="UnauthorizedAccessException">
    /// Thrown if the process does not have write access to the target path or its parent directory.
    /// </exception>
    public void Save()
    {
        var plaintext = SecretSerializer.Serialize(root);

        SecretEncryptor.Encrypt(plaintext, password, out byte[] salt, out byte[] nonce, out byte[] ciphertext, out byte[] tag);

        // Ensure the containing directory exists; this handles first-time saves to a new path
        // such as the default ~/.secretstore location.
        var dir = Path.GetDirectoryName(path);

        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        SecretFileWriter.Write(path, salt, nonce, ciphertext, tag);
    }

    /// <summary>
    /// Returns the decrypted secret tree as a formatted JSON string.
    /// </summary>
    /// <remarks>
    /// The output is indented plaintext JSON. Callers are responsible for ensuring
    /// this value is not written to insecure locations (logs, unencrypted files, etc.).
    /// </remarks>
    /// <returns>A UTF-8 JSON string representing all secrets in the store.</returns>
    public string ExportJson() => SecretSerializer.ExportJson(root);

    /// <summary>
    /// Replaces the entire in-memory secret tree by deserializing the supplied JSON string.
    /// </summary>
    /// <remarks>
    /// This is a full replacement — all existing in-memory secrets are discarded.
    /// The new tree is not persisted until <see cref="Save"/> is called.
    /// Intended for bulk import scenarios (e.g. migrating from a plaintext JSON vault).
    /// </remarks>
    /// <param name="json">A JSON object string whose structure mirrors the desired secret tree.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="json"/> is null or whitespace.</exception>
    public void ImportJson(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        root = SecretSerializer.DeserializeJson(json);
    }
}
