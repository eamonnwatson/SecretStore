using System.Text.Json.Nodes;

namespace SecretStore.Core;

// Provides colon-delimited path navigation over a JsonNode tree.
// All secret keys are stored in a nested JsonObject hierarchy; colons in a path
// represent object nesting levels (e.g. "aws:prod:key" → root["aws"]["prod"]["key"]).
internal static class SecretPath
{
    // Splits a colon-delimited path into its component segments.
    // RemoveEmptyEntries and TrimEntries ensure that leading/trailing colons and accidental
    // double-colons do not produce empty keys that would corrupt the tree.
    private static string[] Split(string path) =>
        path.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    // Traverses the node tree following the path segments and returns the leaf value as a string.
    // Returns null rather than throwing if any segment is missing or if the resolved node is not
    // a leaf value — this allows callers to distinguish "not found" from "found but not a scalar".
    internal static string? Get(JsonNode root, string path)
    {
        var parts = Split(path);
        JsonNode? current = root;

        for (var i = 0; i < parts.Length; i++)
        {
            // If the current node is not an object we cannot descend further — path is invalid.
            if (current is not JsonObject obj)
                return null;
            if (!obj.TryGetPropertyValue(parts[i], out current) || current is null)
                return null;
        }

        // Only return a value for leaf (JsonValue) nodes. Returning null for intermediate objects
        // preserves the invariant that Get never exposes a serialised sub-tree as a secret.
        return current is JsonValue val ? val.ToString() : null;
    }

    // Writes a value to the tree at the specified path, creating intermediate JsonObject nodes
    // on demand. If a segment already exists but is not a JsonObject, it is replaced — this
    // allows promoting a leaf key into a namespace (e.g. setting "aws:key" after "aws" was a leaf).
    internal static void Set(JsonNode root, string path, string value)
    {
        var parts = Split(path);

        if (parts.Length == 0)
            throw new ArgumentException("Path must not be empty.", nameof(path));

        JsonObject current = root as JsonObject
            ?? throw new InvalidOperationException("Root must be a JsonObject.");

        // Walk all segments except the last, auto-creating intermediate objects as needed.
        for (var i = 0; i < parts.Length - 1; i++)
        {
            if (!current.TryGetPropertyValue(parts[i], out var child) || child is not JsonObject childObj)
            {
                childObj = new JsonObject();
                current[parts[i]] = childObj;
            }
            current = childObj;
        }

        // Set the final leaf value using the last path segment.
        current[parts[^1]] = JsonValue.Create(value);
    }

    // Removes the leaf key at the given path without disturbing parent nodes.
    // Returns false silently if any segment of the path does not exist, making Remove idempotent.
    internal static bool Remove(JsonNode root, string path)
    {
        var parts = Split(path);

        if (parts.Length == 0)
            return false;

        JsonObject? current = root as JsonObject;

        // Traverse to the direct parent of the target key.
        for (var i = 0; i < parts.Length - 1; i++)
        {
            if (current is null || !current.TryGetPropertyValue(parts[i], out var child))
                return false;
            current = child as JsonObject;
        }

        return current?.Remove(parts[^1]) ?? false;
    }

    // Exists returns true for both leaf secrets and intermediate namespace nodes.
    // This allows callers to confirm a namespace key (e.g. "aws") is occupied without
    // requiring it to be a scalar value.
    internal static bool Exists(JsonNode root, string path)
        => Get(root, path) is not null || ExistsNode(root, path);

    // Traverses the tree to check whether any node (value or object) exists at the path,
    // complementing Get which only returns non-null for leaf values.
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

    // Returns the fully qualified colon-delimited path for every leaf value in the tree.
    // Intermediate namespace nodes are intentionally excluded so the list represents only
    // actionable secret paths that can be passed directly to Get/Set/Remove.
    internal static IEnumerable<string> List(JsonNode root)
    {
        return Enumerate(root, string.Empty);
    }

    // Recursively enumerates leaf paths using a depth-first traversal.
    // The prefix accumulates the colon-separated path as the recursion descends,
    // so no string joining is needed at the point of yielding each leaf.
    private static IEnumerable<string> Enumerate(JsonNode? node, string prefix)
    {
        if (node is JsonObject obj)
        {
            foreach (var kvp in obj)
            {
                string key = prefix.Length == 0 ? kvp.Key : $"{prefix}:{kvp.Key}";
                if (kvp.Value is JsonObject)
                {
                    // Descend into nested objects, accumulating the path prefix.
                    foreach (string child in Enumerate(kvp.Value, key))
                        yield return child;
                }
                else
                {
                    // Leaf node — yield its fully qualified path.
                    yield return key;
                }
            }
        }
    }
}

