using SecretStore.Core.Serialization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SecretStore.Core;

// Handles the UTF-8 JSON ↔ JsonNode conversions used by the encryption pipeline.
// A single shared JsonSerializerOptions instance is used throughout to avoid
// repeated allocations and to ensure consistent formatting.
internal static class SecretSerializer
{
    // WriteIndented is intentionally enabled so that exported JSON is human-readable.
    // The source-generated context (SecretStoreJsonContext) is required for Native AOT
    // compatibility — reflection-based serialisation is not available in trimmed/AOT builds.
    private static readonly JsonSerializerOptions options = new(SecretStoreJsonContext.Default.Options) { WriteIndented = true };

    // Serialises the in-memory secret tree to a UTF-8 byte array for encryption.
    // Using UTF-8 bytes directly avoids an intermediate string allocation and matches
    // the byte[] input expected by AES-GCM.
    internal static byte[] Serialize(JsonNode root)
    {
        var json = root.ToJsonString(options);
        return Encoding.UTF8.GetBytes(json);
    }

    // Deserialises a UTF-8 byte array (the decrypted ciphertext) back to a JsonNode tree.
    // AllowTrailingCommas and CommentHandling.Skip are enabled to be tolerant of JSON that
    // may have been hand-edited or produced by tools that emit those non-standard features.
    // A null parse result (e.g. a bare JSON null literal) is promoted to an empty object
    // so the caller always receives a usable, mutable tree root.
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

    // Deserialises a raw JSON string for the import workflow.
    // Applies the same tolerant parsing options as Deserialize(byte[]) so that JSON files
    // with comments or trailing commas (common in config files) import without error.
    internal static JsonNode DeserializeJson(string json)
    {
        var node = JsonNode.Parse(json, nodeOptions: null, documentOptions: new JsonDocumentOptions
        {
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip,
        });

        return node ?? new JsonObject();
    }

    // Produces a formatted JSON string of the entire secret tree for the export command.
    // The output is plaintext and must be treated as sensitive by the caller.
    internal static string ExportJson(JsonNode root)
        => root.ToJsonString(options);

}
