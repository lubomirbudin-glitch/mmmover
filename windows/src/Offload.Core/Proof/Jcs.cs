using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Offload.Core.Proof;

/// RFC 8785 (JSON Canonicalization Scheme) for the subset the proof manifest uses: objects, arrays, strings, booleans, null
/// and integers in +-(2^53-1). Any other number is an ArgumentException (no float formatting to get wrong).
public static class Jcs
{
    const long MaxSafe = 9007199254740991;

    public static byte[] Serialize(JsonNode? node) => new UTF8Encoding(false).GetBytes(ToText(node));

    public static string ToText(JsonNode? node)
    {
        var sb = new StringBuilder();
        Write(sb, node);
        return sb.ToString();
    }

    static void Write(StringBuilder sb, JsonNode? node)
    {
        switch (node)
        {
            case null:
                sb.Append("null");
                break;
            case JsonObject o:
                sb.Append('{');
                bool first = true;
                foreach (var key in o.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal))
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteString(sb, key);
                    sb.Append(':');
                    Write(sb, o[key]);
                }
                sb.Append('}');
                break;
            case JsonArray a:
                sb.Append('[');
                for (int i = 0; i < a.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    Write(sb, a[i]);
                }
                sb.Append(']');
                break;
            case JsonValue v:
                switch (v.GetValueKind())
                {
                    case JsonValueKind.String: WriteString(sb, v.GetValue<string>()); break;
                    case JsonValueKind.True: sb.Append("true"); break;
                    case JsonValueKind.False: sb.Append("false"); break;
                    case JsonValueKind.Null: sb.Append("null"); break;
                    case JsonValueKind.Number:
                        if (!TryInteger(v, out var n) || n is > MaxSafe or < -MaxSafe)
                            throw new ArgumentException("Only integers in +-(2^53-1) are supported: " + v.ToJsonString());
                        sb.Append(n.ToString(CultureInfo.InvariantCulture));
                        break;
                    default: throw new ArgumentException("Unsupported JSON value: " + v.GetValueKind());
                }
                break;
        }
    }

    /// An integer-valued JsonValue: long, int, short, byte ... or a JsonElement number that is an integer.
    static bool TryInteger(JsonValue v, out long n)
    {
        if (v.TryGetValue(out n)) return true;
        if (v.TryGetValue<int>(out var i)) { n = i; return true; }
        if (v.TryGetValue<short>(out var sh)) { n = sh; return true; }
        if (v.TryGetValue<sbyte>(out var sb)) { n = sb; return true; }
        if (v.TryGetValue<byte>(out var b)) { n = b; return true; }
        if (v.TryGetValue<ushort>(out var us)) { n = us; return true; }
        if (v.TryGetValue<uint>(out var ui)) { n = ui; return true; }
        if (v.TryGetValue<ulong>(out var ul) && ul <= long.MaxValue) { n = (long)ul; return true; }
        n = 0;
        return false;
    }

    static void WriteString(StringBuilder sb, string s)
    {
        sb.Append('"');
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
                    {
                        sb.Append(c).Append(s[i + 1]);
                        i++;
                    }
                    else if (char.IsSurrogate(c)) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }
}
