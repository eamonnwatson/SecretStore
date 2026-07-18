using SecretStore.Core.Serialization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SecretStore.Core;

internal static class SecretSerializer
{
    private static readonly JsonSerializerOptions options = new(SecretStoreJsonContext.Default.Options) { WriteIndented = true };

    internal static byte[] Serialize(JsonNode root)
    {
        var json = root.ToJsonString(options);
        return Encoding.UTF8.GetBytes(json);
    }

    internal static JsonNode Deserialize(byte[] utf8)
    {
        var json = Encoding.UTF8.GetString(utf8);
        var node = JsonNode.Parse(json, nodeOptions: null, documentOptions: new JsonDocumentOptions
        {
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip,
        });

        return node ?? new JsonObject();
    }

    internal static JsonNode DeserializeJson(string json)
    {
        var node = JsonNode.Parse(json, nodeOptions: null, documentOptions: new JsonDocumentOptions
        {
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip,
        });

        return node ?? new JsonObject();
    }

    internal static string ExportJson(JsonNode root)
        => root.ToJsonString(options);

}
