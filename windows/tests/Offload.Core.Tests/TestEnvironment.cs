using System.Runtime.CompilerServices;
using Offload.Core.History;
using Offload.Core.Proof;

namespace Offload.Core.Tests;

static class TestEnvironment
{
    internal static string HistoryRoot => Path.Combine(Path.GetTempPath(), "offload-tests");

    /// Every OffloadJob a test runs records history (R27). Without this it would land in the developer's own
    /// %APPDATA%\mmMover\history.json — set once, before any test, independent of OFFLOAD_SETTINGS_DIR (which
    /// SettingsStoreTests.AppDataFolder_Override changes for a moment). Stale folders of earlier runs are removed (M8).
#pragma warning disable CA2255 // a test assembly: the initializer only isolates the tests' own app data
    [ModuleInitializer]
    internal static void IsolateHistory()
    {
        try
        {
            if (Directory.Exists(HistoryRoot))
                foreach (var pattern in new[] { "history-*", "appdata-*" })
                    foreach (var old in Directory.EnumerateDirectories(HistoryRoot, pattern))
                        try { Directory.Delete(old, recursive: true); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        HistoryStore.DefaultFolderOverride = Path.Combine(HistoryRoot, "history-" + Environment.ProcessId);
        // Everything else the app keeps in %APPDATA%\mmMover (own LUTs in luts\, settings, update state) goes to a temp
        // folder too, through the app's own seam — the developer's own files never change a test (or the other way round).
        var appData = Path.Combine(HistoryRoot, "appdata-" + Environment.ProcessId);
        Directory.CreateDirectory(appData);
        // Every name (0.11.0: MMMOVER_SETTINGS_DIR wins, then ARCLOADER_ and OFFLOAD_SETTINGS_DIR, which still work): a
        // shell with any of them set never leads a test to the developer's own folder.
        Environment.SetEnvironmentVariable("MMMOVER_SETTINGS_DIR", appData);
        Environment.SetEnvironmentVariable("ARCLOADER_SETTINGS_DIR", appData);
        Environment.SetEnvironmentVariable("OFFLOAD_SETTINGS_DIR", appData);
        // Task 2026-10-09: the local report copies of CLI and settings-made jobs go to %TEMP%, never the real Documents.
        Offload.Core.Outputs.LocalReports.DocumentsOverride = Path.Combine(HistoryRoot, "history-" + Environment.ProcessId, "Documents");
        // Plan 11 (Offload Proof): the proof queue lives in %TEMP% too, and the default service options are offline — no
        // calendar, no block explorer, no calendar allowed for an upgrade — so a job that seals a proof never touches the
        // network; a test that wants calendars brings its own (LocalHttp).
        ProofStore.DefaultFolderOverride = Path.Combine(HistoryRoot, "history-" + Environment.ProcessId, "proof");
        ProofServiceOptions.DefaultOverride = () => new ProofServiceOptions { Calendars = [], HeaderSources = [], AllowedCalendar = _ => false };
        ProofVerifyOptions.DefaultOverride = () => new ProofVerifyOptions { HeaderSources = [] };
        // Synthetic block headers (OtsNetworkTests.Mine, regtest difficulty) pass the proof-of-work check of the faked
        // explorers; a real header passes either way, and HasProofOfWork(MainnetPowLimit) tests Bitcoin's own limit.
        Offload.Core.Proof.Ots.BitcoinHeaders.PowLimitOverride = OtsNetworkTests.RegtestPowLimit;
    }
#pragma warning restore CA2255
}

public class TestEnvironmentTests
{
    [Fact]
    public void HistoryRedirect_IsActive_NeverTheRealAppData()
    {
        var folder = HistoryStore.Default().Folder;
        Assert.Equal(Path.Combine(TestEnvironment.HistoryRoot, "history-" + Environment.ProcessId), folder);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        Assert.False(folder.StartsWith(appData, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ProofSeams_TempFolder_Offline()
    {
        Assert.Equal(Path.Combine(TestEnvironment.HistoryRoot, "history-" + Environment.ProcessId, "proof"), ProofStore.DefaultFolder);
        var o = ProofServiceOptions.Default();
        Assert.Empty(o.Calendars);
        Assert.Empty(o.HeaderSources);
        Assert.False(o.AllowedCalendar("https://alice.btc.calendar.opentimestamps.org"));
        Assert.Null(o.Handler);
        Assert.Equal(OtsNetworkTests.RegtestPowLimit, Offload.Core.Proof.Ots.BitcoinHeaders.PowLimit);
        var v = ProofVerifyOptions.Default();
        Assert.Empty(v.HeaderSources);
        Assert.Null(v.Handler);
        Assert.False(v.Offline);
        Assert.Equal(["https://blockstream.info/api", "https://mempool.space/api"], new ProofVerifyOptions().HeaderSources);
        Assert.Equal(TimeSpan.FromSeconds(10), new ProofVerifyOptions().Timeout);
    }
}
