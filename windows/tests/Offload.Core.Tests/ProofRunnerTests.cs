using Offload.Core.Proof;

namespace Offload.Core.Tests;

/// Plan 11, Task 9: the app works the proof queue in the background, one run at a time — the start, the 10-minute
/// timer, a sealed proof and a disk that arrives never pile up runs, and the caller (a job holding the card folders'
/// lock, the UI thread) is never the one that runs it.
public class ProofRunnerTests
{
    // The pool may be busy for seconds under the whole suite (TestThreads): generous waits.
    static readonly TimeSpan Wait = TimeSpan.FromSeconds(30);

    [Fact]
    public async Task RequestsDuringARun_MakeExactlyOneMoreRun()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var started = new SemaphoreSlim(0);
        int runs = 0;
        var runner = new ProofRunner(async _ =>
        {
            Interlocked.Increment(ref runs);
            started.Release();
            await release.Task;
        }, CancellationToken.None);

        runner.Request();
        Assert.True(await started.WaitAsync(Wait));
        for (int i = 0; i < 5; i++) runner.Request();   // the timer, two sealed proofs, two disks — while the first run works
        Assert.Equal(1, Volatile.Read(ref runs));
        release.SetResult();
        await runner.Idle.WaitAsync(Wait);
        Assert.Equal(2, Volatile.Read(ref runs));

        runner.Request();   // idle again: a new request is a new run
        await runner.Idle.WaitAsync(Wait);
        Assert.Equal(3, Volatile.Read(ref runs));
    }

    [Fact]
    public async Task Request_ReturnsAtOnce_TheRunIsOnAnotherThread()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var ran = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        var runner = new ProofRunner(async _ =>
        {
            ran.TrySetResult(Environment.CurrentManagedThreadId);
            await release.Task;
        }, CancellationToken.None);

        int caller = Environment.CurrentManagedThreadId;
        runner.Request();   // the run blocks until released: Request must not wait for it
        Assert.NotEqual(caller, await ran.Task.WaitAsync(Wait));
        release.SetResult();
        await runner.Idle.WaitAsync(Wait);
    }

    [Fact]
    public async Task Stopped_NothingNewStarts_TheRunInFlightGetsTheToken()
    {
        using var stop = new CancellationTokenSource();
        var started = new SemaphoreSlim(0);
        int runs = 0;
        bool sawCancel = false;
        var runner = new ProofRunner(async ct =>
        {
            Interlocked.Increment(ref runs);
            started.Release();
            try
            {
                await Task.Delay(Timeout.Infinite, ct);
            }
            catch (OperationCanceledException)
            {
                sawCancel = true;   // RunDue stops quietly at its next step
            }
        }, stop.Token);

        runner.Request();
        Assert.True(await started.WaitAsync(Wait));
        runner.Request();   // would be one more run …
        stop.Cancel();      // … but the app closes
        await runner.Idle.WaitAsync(Wait);
        Assert.True(sawCancel);
        runner.Request();
        await runner.Idle.WaitAsync(Wait);
        Assert.Equal(1, Volatile.Read(ref runs));
    }

    [Fact]
    public async Task AFailingRun_IsALogLine_AndTheNextRequestRunsAgain()
    {
        var log = new List<string>();
        int runs = 0;
        var runner = new ProofRunner(_ =>
        {
            if (Interlocked.Increment(ref runs) == 1) throw new IOException("disk gone");
            return Task.CompletedTask;
        }, CancellationToken.None, line => { lock (log) log.Add(line); });

        runner.Request();
        await runner.Idle.WaitAsync(Wait);
        runner.Request();
        await runner.Idle.WaitAsync(Wait);
        Assert.Equal(2, Volatile.Read(ref runs));
        lock (log) Assert.Equal(["proof queue: disk gone"], log);
    }
}
