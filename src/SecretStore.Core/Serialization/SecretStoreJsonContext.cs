using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace SecretStore.Core.Serialization;

// Source-generated JSON serialisation context for the core JsonNode types used by the secret tree.
//
// Why source generation?
// SecretStore.CLI is published as a Native AOT executable (see win-x64-aot.pubxml). AOT compilation
// trims unreachable code and removes reflection metadata. Without a source-generated context,
// System.Text.Json would fail at runtime when attempting to serialise/deserialise JsonNode types
// because their reflection-based converters are stripped during trimming.
//
// Any new type that requires JSON serialisation within SecretStore.Core must be registered here
// (or in its own context) with a [JsonSerializable] attribute, otherwise AOT builds will fail.
[JsonSerializable(typeof(JsonObject))]
[JsonSerializable(typeof(JsonNode))]
[JsonSerializable(typeof(JsonArray))]
[JsonSerializable(typeof(JsonValue))]
[JsonSourceGenerationOptions(
    WriteIndented = true,
    AllowTrailingCommas = true,
    ReadCommentHandling = JsonCommentHandling.Skip)]
internal sealed partial class SecretStoreJsonContext : JsonSerializerContext
{
}
