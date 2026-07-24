using Microsoft.Extensions.Configuration;
using System.Text.RegularExpressions;

namespace SecretStore.Extensions.Configuration;

/// <summary>
/// A configuration provider that scans all previously loaded configuration values
/// for <c>${secret:colon:path}</c> placeholders and replaces them with decrypted
/// values from the encrypted secret store file.
/// </summary>
/// <remarks>
/// This provider must be registered <em>last</em> in the configuration chain so
/// that all other providers' values are available for placeholder scanning.
/// Only configuration keys whose values contain at least one placeholder are
/// written into this provider's <see cref="ConfigurationProvider.Data"/>;
/// all other keys are left untouched in their original providers.
/// </remarks>
internal partial class SecretStoreConfigurationProvider(string filePath, string password, IConfigurationRoot configurationRoot) : ConfigurationProvider
{
    /// <summary>
    /// Matches the <c>${secret:&lt;key&gt;}</c> placeholder syntax used in
    /// configuration values. The capture group extracts the colon-delimited
    /// secret path (e.g. <c>aws:prod:access_key_id</c>).
    /// </summary>
    private static readonly Regex PlaceholderRegex = SecretPlaceholderPattern();

    /// <summary>
    /// Loads secrets by scanning existing configuration for placeholders,
    /// opening the encrypted store, and substituting resolved values.
    /// </summary>
    public override void Load()
    {
        // Phase 1 – Discover which secret keys are actually referenced.
        var placeholderKeys = CollectPlaceholderKeys();

        if (placeholderKeys.Count == 0)
            return;

        // Phase 2 – Decrypt the store and resolve every referenced key.
        var resolvedSecrets = ResolveSecrets(placeholderKeys);

        // Phase 3 – Replace placeholder tokens with real secret values.
        SubstitutePlaceholders(resolvedSecrets);
    }

    /// <summary>
    /// Scans all key-value pairs from earlier configuration providers and
    /// extracts the distinct set of secret keys referenced via placeholders.
    /// </summary>
    private HashSet<string> CollectPlaceholderKeys()
    {
        // Case-insensitive to match the store's key lookup behavior.
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var kvp in configurationRoot.AsEnumerable())
        {
            if (kvp.Value is null)
                continue;

            var matches = PlaceholderRegex.Matches(kvp.Value);

            // Group[1] contains the colon-delimited secret path inside ${secret:…}.
            foreach (Match match in matches)
                keys.Add(match.Groups[1].Value);

        }

        return keys;
    }

    /// <summary>
    /// Opens the encrypted store and retrieves values for every requested key.
    /// Throws if any referenced key is missing, ensuring fail-fast behaviour
    /// rather than silently leaving placeholders unresolved at runtime.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the store file cannot be found, cannot be decrypted, or is
    /// missing one or more keys that configuration placeholders reference.
    /// </exception>
    private Dictionary<string, string> ResolveSecrets(HashSet<string> placeholderKeys)
    {
        try
        {
            var store = Core.SecretStore.Open(filePath, password);
            var resolved = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var missingKeys = new List<string>();

            foreach (var key in placeholderKeys)
            {
                try
                {
                    var value = store.Get(key);

                    if (value is not null)
                        resolved[key] = value;
                    else
                        missingKeys.Add(key);

                }
                catch (KeyNotFoundException)
                {
                    missingKeys.Add(key);
                }
            }

            // Fail fast: every placeholder must resolve to a secret.
            // Partial resolution would leave raw ${secret:…} tokens in config
            // values, which downstream code would misinterpret as literal strings.
            if (missingKeys.Count > 0)
                throw new InvalidOperationException($"Secret store is missing required keys: {string.Join(", ", missingKeys)}");

            return resolved;
        }
        catch (FileNotFoundException ex)
        {
            throw new InvalidOperationException($"Secret store file not found: '{filePath}'. Verify the --secretfile path.", ex);
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            // Wrap decryption / IO errors so callers see a uniform exception type.
            throw new InvalidOperationException($"Failed to load secret store '{filePath}': {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Re-scans configuration values and replaces each <c>${secret:…}</c> token
    /// with its resolved plaintext. Results are written into this provider's
    /// <see cref="ConfigurationProvider.Data"/> dictionary, which takes
    /// precedence over earlier providers for the same key.
    /// </summary>
    private void SubstitutePlaceholders(Dictionary<string, string> resolvedSecrets)
    {
        foreach (var kvp in configurationRoot.AsEnumerable())
        {
            if (kvp.Value is null || !PlaceholderRegex.IsMatch(kvp.Value))
                continue;

            // A single value may contain multiple placeholders
            // (e.g. "Server=${secret:db:host};Password=${secret:db:pass}").
            var resolvedValue = PlaceholderRegex.Replace(kvp.Value, match =>
            {
                var key = match.Groups[1].Value;
                return resolvedSecrets[key];
            });

            Data[kvp.Key] = resolvedValue;
        }
    }

    /// <summary>
    /// Source-generated regex for the <c>${secret:&lt;key&gt;}</c> placeholder syntax.
    /// </summary>
    [GeneratedRegex(@"\$\{secret:([^}]+)\}", RegexOptions.IgnoreCase)]
    private static partial Regex SecretPlaceholderPattern();
}
