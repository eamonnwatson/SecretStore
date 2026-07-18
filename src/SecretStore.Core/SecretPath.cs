using System.Text.Json.Nodes;

namespace SecretStore.Core;

internal static class SecretPath
{
    private static string[] Split(string path) =>
        path.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    internal static string? Get(JsonNode root, string path)
    {
        var parts = Split(path);
        JsonNode? current = root;

        for (var i = 0; i < parts.Length; i++)
        {
            if (current is not JsonObject obj)
                return null;
            if (!obj.TryGetPropertyValue(parts[i], out current) || current is null)
                return null;
        }

        return current is JsonValue val ? val.ToString() : null;
    }

    internal static void Set(JsonNode root, string path, string value)
    {
        var parts = Split(path);

        if (parts.Length == 0)
            throw new ArgumentException("Path must not be empty.", nameof(path));

        JsonObject current = root as JsonObject
            ?? throw new InvalidOperationException("Root must be a JsonObject.");

        for (var i = 0; i < parts.Length - 1; i++)
        {
            if (!current.TryGetPropertyValue(parts[i], out var child) || child is not JsonObject childObj)
            {
                childObj = new JsonObject();
                current[parts[i]] = childObj;
            }
            current = childObj;
        }

        current[parts[^1]] = JsonValue.Create(value);
    }

    internal static bool Remove(JsonNode root, string path)
    {
        var parts = Split(path);

        if (parts.Length == 0)
            return false;

        JsonObject? current = root as JsonObject;

        for (var i = 0; i < parts.Length - 1; i++)
        {
            if (current is null || !current.TryGetPropertyValue(parts[i], out var child))
                return false;
            current = child as JsonObject;
        }

        return current?.Remove(parts[^1]) ?? false;
    }

    internal static bool Exists(JsonNode root, string path)
        => Get(root, path) is not null || ExistsNode(root, path);

    private static bool ExistsNode(JsonNode root, string path)
    {
        var parts = Split(path);
        JsonNode? current = root;

        for (var i = 0; i < parts.Length; i++)
        {
            if (current is not JsonObject obj)
                return false;
            if (!obj.TryGetPropertyValue(parts[i], out current) || current is null)
                return false;
        }

        return true;
    }

    internal static IEnumerable<string> List(JsonNode root)
    {
        return Enumerate(root, string.Empty);
    }

    private static IEnumerable<string> Enumerate(JsonNode? node, string prefix)
    {
        if (node is JsonObject obj)
        {
            foreach (var kvp in obj)
            {
                string key = prefix.Length == 0 ? kvp.Key : $"{prefix}:{kvp.Key}";
                if (kvp.Value is JsonObject)
                {
                    foreach (string child in Enumerate(kvp.Value, key))
                        yield return child;
                }
                else
                {
                    yield return key;
                }
            }
        }
    }
}
