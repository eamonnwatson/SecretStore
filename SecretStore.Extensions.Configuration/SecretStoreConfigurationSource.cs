using Microsoft.Extensions.Configuration;

namespace SecretStore.Extensions.Configuration;

/// <summary>
/// Configuration source that creates a <see cref="SecretStoreConfigurationProvider"/>
/// capable of resolving <c>${secret:…}</c> placeholders against the encrypted store.
/// </summary>
internal class SecretStoreConfigurationSource(string filePath, string password) : IConfigurationSource
{
    public IConfigurationProvider Build(IConfigurationBuilder builder)
    {
        // The provider needs access to the already-built configuration tree so it
        // can scan values from earlier providers for secret placeholders. The host
        // passes the builder as IConfigurationRoot during the second build phase.
        if (builder is not IConfigurationRoot root)
            throw new InvalidOperationException("Configuration builder must be an IConfigurationRoot instance.");

        return new SecretStoreConfigurationProvider(filePath, password, root);
    }
}