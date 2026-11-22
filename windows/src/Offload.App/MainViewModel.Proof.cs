using System.Windows.Threading;
using Offload.Core.Desktop;
using Offload.Core.Proof;

namespace Offload.App;

/// Plan 11 (Offload Proof) in the app: one ProofService over the default queue (%APPDATA%\mmMover\proof, default
/// options) works it in the background, one run at a time (ProofRunner) — at the start, every 10 minutes, after each
/// proof a job seals and when a disk arrives (a disk connected again gets the finished proof). What it saves updates the
/// proof chip of the job's card on the UI thread. Closing never waits for it: the window's lifetime token stops the run
/// at its next step and the process ends without it (the service is never disposed — a run may still be in flight).
/// Off in the demo (ruling I3: it would ask the calendars and write the disks); the demo shows entries of its own.
public sealed partial class MainViewModel
{
    static readonly TimeSpan ProofInterval = TimeSpan.FromMinutes(10);
    readonly DispatcherTimer proofTimer = new() { Interval = ProofInterval };
    /// What the service last saved of each proof (UI thread only) — the chips of this session's cards read it here, never
    /// from the disk.
    readonly Dictionary<string, ProofEntry> proofEntries = new(StringComparer.Ordinal);
    ProofStore? proofStore;
    ProofRunner? proofRunner;

    void InitProof()
    {
        if (!Allowed(DemoCommand.Proof)) return;
        try
        {
            var store = new ProofStore(ProofStore.DefaultFolder);
            var options = ProofServiceOptions.Default();
            options.Log = AppLog.Write;
            var service = new ProofService(store, options);
            // On the service's thread, after every saved change: to the UI thread.
            service.Changed += e => Dispatch(() => ProofEntrySaved(e));
            proofRunner = new ProofRunner(ct => service.RunDue(ct), lifetime.Token, AppLog.Write);
            proofStore = store;
        }
        catch (Exception e)
        {
            AppLog.Write($"proof queue: {e.Message}");   // never fatal: the offloads go on without it
            return;
        }
        proofTimer.Tick += (_, _) => RunProofs();
        proofTimer.Start();
        RunProofs();   // the start: what an earlier session or the CLI left in the queue
    }

    /// One more run of the queue (coalesced with the one in flight); nothing once closing.
    void RunProofs()
    {
        if (!closing) proofRunner?.Request();
    }

    /// OffloadJob.ProofSealed — on the job's thread, maybe while it holds the card folders' lock: only schedules. The new
    /// entry is read off the UI thread (its card shows "waiting for network" at once) and the queue runs (the stamp).
    internal void ProofSealed(string id)
    {
        if (proofStore is not { } store || proofRunner is not { } runner) return;
        runner.Request();
        Task.Run(() =>
        {
            if (store.Get(id) is { } e) Dispatch(() => ProofEntryRead(e));
        });
    }

    /// Final fix C5: the queue entry a finished job still retries in the background — its card is refreshed once that
    /// ends (ProofId and the chip, or ProofError), as a finished card is not refreshed by the timer.
    void WatchProofQueueing(JobItemViewModel item)
    {
        if (item.Job.ProofQueueing is not { } queueing || item.ProofQueueingWatched) return;
        item.ProofQueueingWatched = true;
        queueing.ContinueWith(_ => Dispatch(item.Refresh), TaskScheduler.Default);
    }

    /// A freshly read entry counts only while the service has saved nothing newer of it (both arrive on the UI thread).
    void ProofEntryRead(ProofEntry e)
    {
        if (!proofEntries.ContainsKey(e.Id)) ProofEntrySaved(e);
    }

    void ProofEntrySaved(ProofEntry e)
    {
        proofEntries[e.Id] = e;
        foreach (var j in Jobs.OfType<JobItemViewModel>())
            if (j.ProofId == e.Id) j.ProofChanged();
    }

    /// The entry of a proof as last saved, null when nothing is known of it (yet).
    internal ProofEntry? ProofEntryOf(string? id) => id != null && proofEntries.TryGetValue(id, out var e) ? e : null;

    /// Closing: no more timer runs (the run in flight stops with the lifetime token, nobody waits for it).
    void StopProofs() => proofTimer.Stop();
}
