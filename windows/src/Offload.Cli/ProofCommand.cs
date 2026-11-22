using System.CommandLine;
using System.Globalization;
using Offload.Core;
using Offload.Core.Proof;

namespace Offload.Cli;

/// Plan 11 (Offload Proof): `mmmover proof verify <file | card folder> [--offline]` (exit 0 OK, 1 FAILED, 2 NOT YET),
/// `proof status` (the queue, one line per proof) and `proof upgrade [<card folder>]` (the queue now, or the .ots files
/// of one card folder in place).
static class ProofCommand
{
    /// Test seams: the queue, the queue's options and the verifier's options (the real ones by default; TestEnvironment
    /// makes the defaults offline).
    internal static Func<ProofStore> Store { get; set; } = ProofStore.Default;
    internal static Func<ProofServiceOptions> ServiceOptions { get; set; } = ProofServiceOptions.Default;
    internal static Func<ProofVerifyOptions> VerifyOptions { get; set; } = ProofVerifyOptions.Default;

    public static Command Create()
    {
        var cmd = new Command("proof", "Offload Proof: check a file or a card folder against its proof; see or finish the proofs in the queue.");
        cmd.Subcommands.Add(VerifyCommand());
        cmd.Subcommands.Add(StatusCommand());
        cmd.Subcommands.Add(UpgradeCommand());
        return cmd;
    }

    static Command VerifyCommand()
    {
        var path = new Argument<string>("path") { Description = "A file of a backup, or a card folder (<root>/<date>/<card>): every file of its proof." };
        var offline = new Option<bool>("--offline") { Description = "Ask no block explorer: check the files, the manifest and what the .ots says (the result is at best NOT YET)." };
        var cmd = new Command("verify",
            "Check that a file (or every file of a card folder) is unchanged and existed no later than the Bitcoin block its proof is anchored in. Exit 0 = OK, 1 = FAILED, 2 = NOT YET.");
        cmd.Arguments.Add(path);
        cmd.Options.Add(offline);
        cmd.SetAction(r => Verify(r.GetValue(path)!, r.GetValue(offline)));
        return cmd;
    }

    static Command StatusCommand()
    {
        var cmd = new Command("status", "The proofs in this computer's queue: card, date, generation, state, Bitcoin block and on how many disks.");
        cmd.SetAction(_ => Status());
        return cmd;
    }

    static Command UpgradeCommand()
    {
        var folder = new Argument<string?>("folder") { Description = "A card folder: upgrade the .ots files in its _REPORT in place, stamp a proof manifest that has none (without it: every proof in the queue, now).", Arity = ArgumentArity.ZeroOrOne };
        var cmd = new Command("upgrade",
            "Ask the calendars for the Bitcoin anchor now: every proof in the queue (stamp, upgrade, write onto the disks), or the .ots files of one card folder.");
        cmd.Arguments.Add(folder);
        cmd.SetAction(r => Upgrade(r.GetValue(folder)));
        return cmd;
    }

    internal static int ExitCode(ProofOutcome o) => o switch { ProofOutcome.Ok => 0, ProofOutcome.Failed => 1, _ => 2 };

    static int Verify(string input, bool offline)
    {
        string full;
        try
        {
            full = CliPath.Full(input);
        }
        catch (Exception e)
        {
            Console.Error.WriteLine(Msg.CliError + e.Message);
            return 1;
        }
        bool isFolder = Directory.Exists(full);
        if (!isFolder && !File.Exists(full))
        {
            Console.Error.WriteLine(Msg.CliError + $"{input} is not a file or a folder.");
            return 1;
        }
        var o = VerifyOptions();
        o.Offline |= offline;
        if (isFolder)
        {
            var last = DateTime.MinValue;
            o.Progress = (path, i, n) =>
            {
                if (DateTime.UtcNow - last < TimeSpan.FromMilliseconds(500)) return;
                last = DateTime.UtcNow;
                ConsoleLine.Write($"{i + 1}/{n}  {path}");
            };
        }
        return WithCancel(async ct =>
        {
            var v = isFolder ? await ProofVerifier.VerifyFolder(full, o, ct) : await ProofVerifier.VerifyFile(full, o, ct);
            ConsoleLine.Clear();
            foreach (var line in v.Lines) Console.WriteLine(line);
            return ExitCode(v.Outcome);
        });
    }

    static int Status()
    {
        var store = Store();
        var all = store.All();
        if (all.Count == 0)
        {
            Console.WriteLine($"No proofs in the queue ({store.Folder}).");
            return 0;
        }
        foreach (var e in all) Console.WriteLine(StatusLine(e));
        return 0;
    }

    /// `A001  2026-11-19  generation 1  anchored in Bitcoin block 800000 (2026-11-19 23:41:07 UTC)  on 2 of 2 disks`
    /// (+ `  — <last error>` while not anchored). `on N of M disks`: the disks holding the .ots — anchored: the complete
    /// one; before: any.
    internal static string StatusLine(ProofEntry e)
    {
        var state = e.State switch
        {
            ProofState.Queued => "waiting for network",
            ProofState.Pending => "anchoring (Bitcoin confirms in a few hours)",
            ProofState.Complete => "anchored" + (e.BitcoinHeight is { } h ? $" in Bitcoin block {h}" : "")
                + (e.BitcoinTime is { } t ? $" ({t.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)} UTC)" : e.BitcoinHeight != null ? " (block time not checked)" : ""),
            _ => "not created",
        };
        int on = e.State == ProofState.Complete
            ? e.Written.Count(w => w == ProofEntry.WrittenComplete)
            : e.Written.Count(w => w != ProofEntry.WrittenNone);
        var card = string.IsNullOrEmpty(e.CardName) ? "?" : e.CardName;
        var line = $"{card}  {e.Date}  generation {e.Generation}  {state}  on {on} of {e.CardPaths.Count} disk{(e.CardPaths.Count == 1 ? "" : "s")}";
        return e.State != ProofState.Complete && !string.IsNullOrEmpty(e.LastError) ? $"{line}  — {e.LastError}" : line;
    }

    static int Upgrade(string? folder)
    {
        string? full = null;
        if (folder != null)
        {
            try
            {
                full = CliPath.Full(folder);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(Msg.CliError + e.Message);
                return 1;
            }
            if (!Directory.Exists(full))
            {
                Console.Error.WriteLine(Msg.CliError + $"{folder} is not a folder.");
                return 1;
            }
        }
        var store = Store();
        var options = ServiceOptions();
        options.Log ??= m => Console.Error.WriteLine(m);
        using var service = new ProofService(store, options);
        return WithCancel(async ct =>
        {
            if (full != null)
            {
                if (await service.UpgradeFolder(full, ct) is not { } lines)
                {
                    Console.Error.WriteLine(Msg.CliError + $"no proof manifest or timestamp (.ots) in {Path.Combine(full, Layout.ReportDirName)}.");
                    return 1;
                }
                foreach (var line in lines) Console.WriteLine(line);
                return 0;
            }
            var worked = await service.RunDue(ct, force: true);
            if (ct.IsCancellationRequested) throw new OperationCanceledException(ct);
            if (worked.Count == 0) Console.WriteLine("Nothing to do — no proof in the queue waits for the calendars or for a disk (mmmover proof status lists them).");
            foreach (var e in worked) Console.WriteLine(StatusLine(e));
            return 0;
        });
    }

    /// Runs `work` with Ctrl+C as its cancellation (exit 1, "Cancelled.").
    static int WithCancel(Func<CancellationToken, Task<int>> work)
    {
        using var cancel = new CancellationTokenSource();
        ConsoleCancelEventHandler onCtrlC = (_, e) =>
        {
            e.Cancel = true;
            try { cancel.Cancel(); }
            catch (ObjectDisposedException) { }
        };
        Console.CancelKeyPress += onCtrlC;
        try
        {
            return work(cancel.Token).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested)
        {
            ConsoleLine.Clear();
            Console.Error.WriteLine("Cancelled.");
            return 1;
        }
        finally
        {
            Console.CancelKeyPress -= onCtrlC;
        }
    }
}
