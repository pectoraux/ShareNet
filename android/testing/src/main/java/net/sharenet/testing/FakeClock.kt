package net.sharenet.testing

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.time.Duration
import java.time.Instant

/**
 * Controllable clock for deterministic tests.
 *
 * All time in epoch millis. Starts at a fixed instant (2025-01-01T00:00:00Z) so
 * tests are reproducible regardless of wall clock. Use [advanceBy] to move time
 * forward without real delay; use [advanceAndDelay] if the code under test
 * relies on `delay` (e.g. WorkManager backoff).
 *
 * Mirrors `kotlinx.coroutines.test.TestScope` clock but is a standalone type so
 * production code can depend on it without pulling `kotlinx-coroutines-test`.
 *
 * @param startMs initial time in epoch millis.
 */
class FakeClock(startMs: Long = DEFAULT_START_MS) {

    companion object {
        /** 2025-01-01T00:00:00Z */
        const val DEFAULT_START_MS: Long = 1735689600000L
    }

    private val _nowMs = MutableStateFlow(startMs)
    /** Observable clock for reactive code. */
    val nowFlow: StateFlow<Long> = _nowMs.asStateFlow()

    /** Current time in epoch millis. */
    fun now(): Long = _nowMs.value

    /** Current time as [Instant]. */
    fun instant(): Instant = Instant.ofEpochMilli(now())

    /**
     * Advance the clock by [durationMs] millis.
     * No real delay — synchronous.
     */
    fun advanceBy(durationMs: Long) {
        require(durationMs >= 0) { "Cannot go backwards: $durationMs" }
        _nowMs.value += durationMs
    }

    /** Advance by [duration]. */
    fun advanceBy(duration: Duration) = advanceBy(duration.toMillis())

    /** Advance by [millis] and also call [delay] so coroutine `delay` respects the jump in tests that use real delay. */
    suspend fun advanceAndDelay(millis: Long) {
        advanceBy(millis)
        delay(millis)
    }

    /** Set clock to an absolute [epochMs]. Must be >= current. */
    fun setTo(epochMs: Long) {
        require(epochMs >= _nowMs.value) { "Cannot go backwards: $epochMs < ${_nowMs.value}" }
        _nowMs.value = epochMs
    }

    /** Reset to [DEFAULT_START_MS]. */
    fun reset() { _nowMs.value = DEFAULT_START_MS }

    /** Elapsed millis since [startMs]. */
    fun elapsedSince(startMs: Long): Long = _nowMs.value - startMs
}

/**
 * Real clock adapter that delegates to `System.currentTimeMillis()`.
 * Use as the production `clock: () -> Long` argument.
 */
object SystemClock {
    fun now(): Long = System.currentTimeMillis()
}
