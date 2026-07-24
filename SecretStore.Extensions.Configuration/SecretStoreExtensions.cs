using Microsoft.Extensions.Configuration;

namespace SecretStore.Extensions.Configuration;

/// <summary>
/// Extension methods for integrating the encrypted secret store with
/// <see cref="IConfigurationBuilder"/>.
/// </summary>
public static class SecretStoreExtensions
{
    /// <summary>
    /// Registers the encrypted secret store as a configuration source so that
    /// <c>${secret:colon:path}</c> placeholders in previously loaded providers
    /// are replaced with decrypted secret values at configuration-build time.
    /// </summary>
    /// <param name="builder">The configuration builder to extend.</param>
    /// <param name="filePath">
    /// Path to the encrypted store file, typically supplied via command-line or
    /// environment variable. When <see langword="null"/> or empty the secret
    /// store is silently skipped, allowing the application to run without secrets
    /// in environments where they are not required (e.g. local dev without a store file).
    /// </param>
    /// <param name="password">
    /// Master password used to derive the AES-256-GCM decryption key.
    /// When <see langword="null"/> or empty the secret store is silently skipped.
    /// </param>
    /// <returns>The same <see cref="IConfigurationBuilder"/> instance for chaining.</returns>
    public static IConfigurationBuilder AddSecretStore(this IConfigurationBuilder builder, string? filePath, string? password)
    {
        // Silently no-op when credentials are absent so the host can still start
        // without secrets (useful for migrations, health-checks, or local dev).
        if (string.IsNullOrEmpty(filePath) || string.IsNullOrEmpty(password))
            return builder;

        builder.Add(new SecretStoreConfigurationSource(filePath, password));

        return builder;
    }
}