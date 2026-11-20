using System.Text;
using System.Text.Json.Nodes;
using Offload.Core.Proof;

namespace Offload.Core.Tests;

public class JcsTests
{
    [Fact]
    public void Object_KeysOrderedAndEscaped()
    {
        var o = new JsonObject
        {
            ["b"] = 2,
            ["a"] = "€\n\u0001",
            ["c"] = new JsonArray(true, false, null),
            ["€"] = 1,
            ["\r"] = 0,
        };
        Assert.Equal("{\"\\r\":0,\"a\":\"€\\n\\u0001\",\"b\":2,\"c\":[true,false,null],\"€\":1}", Jcs.ToText(o));
    }

    [Fact]
    public void Keys_AreOrderedByUtf16Units()
    {
        // U+1F600 is the surrogate pair D83D DE00, which sorts before U+FF5E (RFC 8785 3.2.3), unlike UTF-8 order.
        var o = new JsonObject { ["\uFF5E"] = 1, ["\U0001F600"] = 2 };
        Assert.Equal("{\"\U0001F600\":2,\"\uFF5E\":1}", Jcs.ToText(o));
    }

    [Fact]
    public void NonIntegersAndHugeIntegers_Throw()
    {
        Assert.Throws<ArgumentException>(() => Jcs.ToText(JsonValue.Create(1.5)));
        Assert.Throws<ArgumentException>(() => Jcs.ToText(JsonValue.Create(9007199254740992L)));
        Assert.Equal("9007199254740991", Jcs.ToText(JsonValue.Create(9007199254740991L)));
        Assert.Equal("-5", Jcs.ToText(JsonNode.Parse("-5")));
        Assert.Throws<ArgumentException>(() => Jcs.ToText(JsonNode.Parse("1.5")));
    }

    [Fact]
    public void LoneSurrogate_IsEscaped_PairStaysLiteral()
    {
        Assert.Equal("\"\\ud800\"", Jcs.ToText(JsonValue.Create("\uD800")));
        Assert.Equal("\"\U0001F600\"", Jcs.ToText(JsonValue.Create("\U0001F600")));
    }

    [Fact]
    public void Output_IsUtf8WithoutBom()
    {
        var bytes = Jcs.Serialize(new JsonObject { ["k"] = "š" });
        Assert.Equal(Encoding.UTF8.GetBytes("{\"k\":\"š\"}"), bytes);
        Assert.NotEqual(0xEF, bytes[0]);
    }
}
