using System.Text.Json.Serialization;

namespace SecretStore.Core;

internal sealed class JweHeader
{
    [JsonPropertyName("alg")]
    public string Alg { get; set; } = default!;

    [JsonPropertyName("enc")]
    public string Enc { get; set; } = default!;

    [JsonPropertyName("p2s")]
    public string P2s { get; set; } = default!;

    [JsonPropertyName("p2c")]
    public int P2c { get; set; }
}

[JsonSerializable(typeof(JweHeader))]
internal sealed partial class JweHeaderContext : JsonSerializerContext;
