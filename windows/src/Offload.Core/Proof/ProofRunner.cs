namespace Offload.Core.Proof;

/// The app's proof queue in the background (plan 11, Task 9): `run` (ProofService.RunDue) on a pool task, one run at a
/// time. A request while a run is in flight makes exactly one more run after it, however many came — the start, the
/// 10-minute timer, a sealed proof and a disk that arrives never pile up. Request never blocks and never works on the
/// caller's thread (a job calls it while it may hold the card folders' lock; the UI thread must stay free). Once `stop`
/// is cancelled (the window closes) nothing new starts and the run in flight gets the cancelled token — nobody waits for
/// it. A run that throws is a log line; the next request runs again.
public sealed class ProofRunner(Func<CancellationToken, Task> run, CancellationToken stop, Action<string>? log = null)
{
    readonly object gate = new();
    bool running, again;
    Task idle = Task.CompletedTask;

    /// Completes once no run is in flight or asked for (tests).
    public Task Idle
    {
        get
        {
            lock (gate) return idle;
        }
    }

    public void Request()
    {
        lock (gate)
        {
            if (stop.IsCancellationRequested) return;
            if (running)
            {
                again = true;
                return;
            }
            running = true;
            idle = Task.Run(Loop, CancellationToken.None);
        }
    }

    async Task Loop()
    {
        while (true)
        {
            try
            {
                await run(stop).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
                // closing: the queue goes on at the next start
            }
            catch (Exception e)
            {
                try
                {
                    log?.Invoke($"proof queue: {e.Message}");
                }
                catch (Exception)
                {
                    // logging never breaks the queue
                }
            }
            lock (gate)
            {
                if (!again || stop.IsCancellationRequested)
                {
                    running = again = false;
                    return;
                }
                again = false;
            }
        }
    }
}
