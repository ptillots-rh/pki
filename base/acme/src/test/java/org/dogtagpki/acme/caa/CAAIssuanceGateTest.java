// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests the boundary between CAA evaluation and permission to submit an
 * issuance request. The gate applies instance configuration, owns the
 * validator, reports decisions and blocks submission when approval is unusable.
 * An in-memory DNS provider drives the real engine, and a recording callback
 * stands in for the issuer. This covers check-then-submit behavior without
 * exercising ACME HTTP processing or actual CA signing.
 */
class CAAIssuanceGateTest {
    private static final DNSDomainName NAME = new DNSDomainName("www.example.com.");
    private static final CAARequest REQUEST = new CAARequest(
            List.of(new CAARequest.CertificateName(NAME, false)), Map.of());

    @BeforeEach
    void reset() {
        TestDNSProvider.opens.set(0);
        TestDNSProvider.closes.set(0);
        TestDNSProvider.lookups.set(0);
        TestDNSProvider.settings = Map.of();
        TestDNSProvider.issuer = "ca.example";
        TestDNSProvider.receivedAt = null;
        TestDNSProvider.clock = Clock.systemUTC();
        TestDNSProvider.nanoTime = System::nanoTime;
        TestDNSProvider.receivedNanos = 0;
        TestDNSProvider.onLookup = () -> {};
        TestDNSProvider.error = false;
        TestDNSProvider.untrusted = false;
        TestDNSProvider.absent = false;
    }

    /**
     * Disable CAA while supplying an absent adapter and unusable settings.
     * Submission must proceed without opening DNS or calling the decision observer.
     */
    @Test
    void disabledPolicyDoesNotLoadAnAbsentProviderOrValidateItsSettings() throws Exception {
        Properties properties = properties();
        properties.setProperty("enabled", "false");
        properties.setProperty("dns.class", "not.installed.Provider");
        properties.setProperty("issuerIdentifiers", "not an issuer");
        properties.setProperty("dns.settings.not-supported", "private-value");

        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties, getClass().getClassLoader())) {
            String result = TestCAAIssuance.submit(gate, null,
                    decision -> fail("Disabled policy observed"), () -> "issued");

            assertFalse(gate.isEnabled());
            assertEquals("issued", result);
        }
        assertEquals(0, TestDNSProvider.opens.get());
    }

    /**
     * Supply unknown configuration keys, including a misspelled enable flag.
     * Reject them rather than silently leaving enforcement disabled.
     */
    @Test
    void misspelledAndLegacySettingsFailBeforeOpeningAProvider() {
        for (String key : List.of("enabeld", "validationMode", "version", "params.accept", "dns.server")) {
            Properties properties = properties();
            properties.setProperty(key, "value");
            if (key.equals("enabeld")) {
                properties.remove("enabled");
            }

            DNSLookupException error = assertThrows(DNSLookupException.class,
                    () -> CAAIssuanceGate.open(properties, getClass().getClassLoader()));
            assertEquals(DNSLookupException.Reason.CONFIGURATION, error.failure().reason());
        }
        assertEquals(0, TestDNSProvider.opens.get());
    }

    /**
     * Programmatic Properties entries must not disappear during string-only
     * enumeration. Exercise explicit values and inherited defaults alike.
     */
    @Test
    void nonStringSettingsFailBeforeDefaultsCanDisableCaa() {
        record InvalidSetting(Object key, Object value) {}
        List<InvalidSetting> cases = List.of(
                new InvalidSetting("enabled", Boolean.TRUE),
                new InvalidSetting("issuerIdentifiers", 123),
                new InvalidSetting("dns.class", 123),
                new InvalidSetting("dns.settings.port", 1053),
                new InvalidSetting("unknown", Boolean.FALSE),
                new InvalidSetting(123, "value"));

        for (InvalidSetting test : cases) {
            Properties invalid = new Properties();
            invalid.put(test.key(), test.value());
            for (Properties settings : List.of(invalid, new Properties(invalid))) {
                DNSLookupException error = assertThrows(DNSLookupException.class,
                        () -> CAAIssuanceGate.open(settings, getClass().getClassLoader()), test.toString());
                assertEquals(DNSLookupException.Reason.CONFIGURATION, error.failure().reason(), test.toString());
            }
        }
        assertEquals(0, TestDNSProvider.opens.get());
    }

    /**
     * Valid string defaults still enable checking. An explicit malformed value
     * must be rejected even if getProperty() would fall back to a string default.
     */
    @Test
    void stringDefaultsWorkButCannotHideMalformedExplicitValues() throws Exception {
        Properties settings = new Properties(properties());
        try (CAAIssuanceGate gate = CAAIssuanceGate.open(settings, getClass().getClassLoader())) {
            assertTrue(gate.isEnabled());
            gate.check(REQUEST, decision -> assertEquals(CAADecision.Outcome.ALLOW, decision.outcome()));
        }

        settings.put("enabled", Boolean.TRUE);
        DNSLookupException error = assertThrows(DNSLookupException.class,
                () -> CAAIssuanceGate.open(settings, getClass().getClassLoader()));
        assertEquals(DNSLookupException.Reason.CONFIGURATION, error.failure().reason());
        assertEquals(1, TestDNSProvider.opens.get());
    }

    /**
     * An inherited Boolean must not be skipped in favor of a deeper string
     * default. Exercise the enable flag and provider settings through both an
     * enabled and disabled fallback before any provider can open.
     */
    @Test
    void inheritedMalformedValuesCannotFallBackToStrings() {
        for (String fallback : List.of("true", "false")) {
            for (String key : List.of("enabled", "issuerIdentifiers", "dns.class", "dns.settings.port")) {
                Properties defaults = properties();
                defaults.setProperty("enabled", fallback);
                // Keep fallback values valid so only the inherited type can fail.
                if (key.equals("dns.settings.port")) {
                    defaults.setProperty(key, "1053");
                }
                Properties malformed = new Properties(defaults);
                malformed.put(key, Boolean.TRUE);
                Properties settings = new Properties(malformed);

                DNSLookupException error = assertThrows(DNSLookupException.class,
                        () -> CAAIssuanceGate.open(settings, getClass().getClassLoader()),
                        key + " with enabled=" + fallback);
                assertEquals(DNSLookupException.Reason.CONFIGURATION, error.failure().reason());
            }
        }
        assertEquals(0, TestDNSProvider.opens.get());
    }

    /**
     * Try empty list elements and URL-shaped issuers in enabled configuration.
     * All must fail before opening DNS, including leading and trailing commas.
     */
    @Test
    void malformedIssuerListsCannotOpenDnsOrBecomePermissive() {
        for (String value : List.of("", ",ca.example", "ca.example,", "ca.example,,other.test", "https://ca.example")) {
            Properties properties = properties();
            properties.setProperty("issuerIdentifiers", value);

            assertThrows(DNSLookupException.class,
                    () -> CAAIssuanceGate.open(properties, getClass().getClassLoader()));
        }
        assertEquals(0, TestDNSProvider.opens.get());
    }

    /**
     * Configure two issuer identifiers and namespaced adapter settings. Verify
     * that settings are copied, the prefix is removed, and the alternate issuer grants.
     */
    @Test
    void acceptsTrimmedMultipleIssuersAndPreservesProviderSettings() throws Exception {
        Properties properties = properties();
        properties.setProperty("issuerIdentifiers", " ca.example , OTHER.example ");
        properties.setProperty("dns.settings.server", "127.0.0.1");
        properties.setProperty("dns.settings.port", "1053");
        TestDNSProvider.issuer = "other.example";

        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties, getClass().getClassLoader())) {
            assertEquals(Map.of("server", "127.0.0.1", "port", "1053"), TestDNSProvider.settings);
            properties.setProperty("dns.settings.server", "changed-after-open");

            assertEquals("127.0.0.1", TestDNSProvider.settings.get("server"));
            gate.check(REQUEST, decision -> assertEquals(CAADecision.Outcome.ALLOW, decision.outcome()));
        }
    }

    /**
     * Report the decision before the consuming flow reaches its submission
     * callback. Actual issuer-failure handling is exercised by the ACME tests.
     */
    @Test
    void observesBeforeExactlyOneSubmission() throws Exception {
        List<String> events = new ArrayList<>();
        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            TestCAAIssuance.submit(gate, REQUEST, decision -> events.add("observe"),
                    () -> events.add("submit"));
            assertEquals(List.of("observe", "submit"), events);
        }
    }

    /**
     * Make the decision observer throw and verify that the issuer is not called.
     * A subsequent attempt with a working observer must still be able to submit.
     */
    @Test
    void observerFailureSuppressesSubmissionAndDoesNotPoisonTheNextCheck() throws Exception {
        AtomicInteger submissions = new AtomicInteger();

        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            Consumer<CAADecision> failingObserver = decision -> {
                throw new IllegalStateException("Decision observer failed");
            };

            assertThrows(IllegalStateException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, failingObserver, submissions::incrementAndGet));
            assertEquals(0, submissions.get());
            int submitted = TestCAAIssuance.submit(gate, REQUEST,
                    decision -> assertEquals(CAADecision.Outcome.ALLOW, decision.outcome()),
                    submissions::incrementAndGet);

            assertEquals(1, submitted);
        }
    }

    /**
     * Interrupt after validation has allowed, while reporting its evidence.
     * The gate must refuse handoff without clearing the interruption flag.
     */
    @Test
    void observerInterruptionBlocksSubmissionAndPreservesTheFlag() throws Exception {
        AtomicInteger submissions = new AtomicInteger();
        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            try {
                CAAIssuanceGate.CAAApprovalException error = assertThrows(
                        CAAIssuanceGate.CAAApprovalException.class,
                        () -> TestCAAIssuance.submit(gate, REQUEST,
                                decision -> Thread.currentThread().interrupt(), submissions::incrementAndGet));

                assertEquals(CAAIssuanceGate.RejectionReason.CANCELLED, error.reason());
                assertEquals(CAADecision.Outcome.ALLOW, error.decision().outcome());
                assertTrue(Thread.currentThread().isInterrupted());
                assertEquals(0, submissions.get());
            } finally {
                Thread.interrupted();
            }

            TestCAAIssuance.submit(gate, REQUEST, decision -> {}, submissions::incrementAndGet);
            assertEquals(1, submissions.get());
        }
    }

    /**
     * Move wall time backward during observation while the elapsed approval
     * lifetime runs out. A still-future expiresAt must not permit submission.
     */
    @Test
    void backwardClockDuringObservationCannotExtendApproval() throws Exception {
        MutableClock clock = new MutableClock();
        Duration maxAge = new CAAPolicy(Set.of("ca.example")).maxDecisionAge();
        try (CAAIssuanceGate gate = timedGate(clock)) {
            CAAIssuanceGate.CAAApprovalException error = assertThrows(
                    CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, decision -> {
                        clock.wallTime = clock.wallTime.minusSeconds(3600);
                        clock.elapsedNanos += maxAge.plusSeconds(1).toNanos();
                    }, () -> fail("Elapsed approval submitted")));

            assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED, error.reason());
            assertEquals(CAADecision.Outcome.ALLOW, error.decision().outcome());
        }
    }

    /**
     * Pause inside the final wall-clock read while elapsed validity ends and
     * wall time steps backward. The elapsed sample must be taken after that read.
     */
    @Test
    void pauseDuringFinalWallReadCannotBypassElapsedExpiry() throws Exception {
        MutableClock clock = new MutableClock();
        Duration maximum = new CAAPolicy(Set.of("ca.example")).maxDecisionAge();
        try (CAAIssuanceGate gate = timedGate(clock)) {
            CAAIssuanceGate.CAAApprovalException error = assertThrows(
                    CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, decision -> {
                        // Arm the next clock read only after validation completes.
                        clock.onRead = () -> {
                            clock.elapsedNanos += maximum.plusSeconds(1).toNanos();
                            clock.wallTime = clock.wallTime.minusSeconds(3600);
                        };
                    }, () -> fail("Stale elapsed sample permitted submission")));

            assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED, error.reason());
            assertEquals(CAADecision.Outcome.ALLOW, error.decision().outcome());
        }
    }

    /**
     * Leave one second on the UTC deadline and two on the elapsed deadline.
     * Pause on either side of the UTC sample. Its margin must cover the
     * entire measured interval, including the exact boundary.
     */
    @Test
    void finalClockSamplingConsumesTheRemainingWallClockMargin() throws Exception {
        record SamplingCase(String label, Duration beforeSample, Duration afterSample, boolean permitted) {}
        List<SamplingCase> cases = List.of(
                new SamplingCase("before UTC expiry", Duration.ZERO, Duration.ofSeconds(1).minusNanos(1), true),
                new SamplingCase("exact UTC expiry", Duration.ZERO, Duration.ofSeconds(1), false),
                new SamplingCase("after UTC expiry", Duration.ZERO, Duration.ofSeconds(1).plusNanos(1), false),
                new SamplingCase("pause around UTC sample", Duration.ofMillis(500), Duration.ofMillis(500), false));
        Duration maximum = new CAAPolicy(Set.of("ca.example")).maxDecisionAge();

        for (SamplingCase test : cases) {
            MutableClock clock = new MutableClock();
            // The interval around the final wall read crosses signed nanoTime rollover.
            clock.elapsedNanos = Long.MAX_VALUE - maximum.toNanos() + Duration.ofMillis(1500).toNanos();
            Consumer<CAADecision> observer = decision -> {
                assertEquals(CAADecision.Outcome.ALLOW, decision.outcome(), test.label());
                clock.wallTime = decision.expiresAt().minusSeconds(1);
                clock.elapsedNanos += maximum.minusSeconds(2).toNanos();
                clock.onRead = () -> {
                    // Keep one second of UTC margin at the actual wall sample.
                    // Time before that sample still consumes the full interval.
                    clock.elapsedNanos += test.beforeSample().toNanos();
                    clock.onElapsedRead = () -> {
                        clock.wallTime = clock.wallTime.plus(test.afterSample());
                        clock.elapsedNanos += test.afterSample().toNanos();
                    };
                };
            };
            try (CAAIssuanceGate gate = timedGate(clock)) {
                if (test.permitted()) {
                    assertEquals("issued", TestCAAIssuance.submit(
                            gate, REQUEST, observer, () -> "issued"), test.label());
                } else {
                    var error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                            () -> TestCAAIssuance.submit(gate, REQUEST, observer,
                                    () -> fail("Submitted after UTC sampling exhausted its margin")), test.label());
                    assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED, error.reason(), test.label());
                }
            }
        }
    }

    /**
     * Move UTC backward while receiving fresh evidence, then correct it during
     * observation. Preserve the original UTC expiry while the shorter elapsed
     * deadline retains the conservative allowance established at entry.
     */
    @Test
    void clockCorrectionDoesNotChargeTheRollbackTwice() throws Exception {
        MutableClock clock = new MutableClock();
        Instant started = clock.wallTime;
        Duration elapsed = Duration.ofMinutes(390);
        TestDNSProvider.onLookup = () -> clock.wallTime = clock.wallTime.minusSeconds(3600);

        try (CAAIssuanceGate gate = timedGate(clock)) {
            String issued = TestCAAIssuance.submit(gate, REQUEST, decision -> {
                assertEquals(CAADecision.Outcome.ALLOW, decision.outcome());
                assertEquals(started.plus(Duration.ofHours(7)), decision.expiresAt());
                assertEquals(Duration.ofHours(7).toNanos(), decision.expiresAtNanos());
                // Six and a half hours elapsed. Correcting the clock still
                // leaves thirty minutes on each applicable deadline.
                clock.elapsedNanos = elapsed.toNanos();
                clock.wallTime = started.plus(elapsed);
            }, () -> "issued");
            assertEquals("issued", issued);
        }
    }

    /**
     * Seven-hour-old evidence has one elapsed hour left. Roll UTC back during
     * lookup and correct it in the observer. That remaining hour stays usable
     * until its exclusive elapsed boundary, independently of the UTC cutoff.
     */
    @Test
    void clockCorrectionPreservesTheRemainingLifetimeOfOlderEvidence() throws Exception {
        Duration remaining = Duration.ofHours(1);
        for (Duration elapsed : List.of(remaining.minusNanos(1), remaining, remaining.plusNanos(1))) {
            MutableClock clock = new MutableClock();
            Instant started = clock.wallTime;
            TestDNSProvider.receivedAt = started;
            TestDNSProvider.receivedNanos = clock.elapsedNanos - Duration.ofHours(7).toNanos();
            TestDNSProvider.onLookup = () -> clock.wallTime = clock.wallTime.minusSeconds(3600);
            Consumer<CAADecision> observer = decision -> {
                assertEquals(CAADecision.Outcome.ALLOW, decision.outcome());
                // UTC retains its own observation-based cutoff. The older
                // evidence's elapsed deadline still permits only one hour.
                assertEquals(started.plus(Duration.ofHours(7)), decision.expiresAt());
                assertEquals(remaining.toNanos(), decision.expiresAtNanos());
                clock.wallTime = started.plus(elapsed);
                clock.elapsedNanos = elapsed.toNanos();
            };

            try (CAAIssuanceGate gate = timedGate(clock)) {
                if (elapsed.compareTo(remaining) < 0) {
                    assertEquals("issued", TestCAAIssuance.submit(gate, REQUEST, observer, () -> "issued"));
                } else {
                    var error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                            () -> TestCAAIssuance.submit(gate, REQUEST, observer,
                                    () -> fail("Old evidence exceeded its remaining lifetime")));
                    assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED, error.reason());
                }
            }
        }
    }

    /**
     * Pause on either side of UTC capture. The earliest possible capture time
     * bounds each margin, so uncertainty can reject nearly expired evidence.
     * Exercise combined pauses and signed nanoTime rollover as well.
     */
    @Test
    void utcSamplingUncertaintyConservativelyBoundsRetainedEvidence() throws Exception {
        record SamplingCase(String label, int initialBefore, int initialAfter,
                int completionBefore, int completionAfter, int deadlineSeconds, boolean permitted) {}
        List<SamplingCase> cases = List.of(
                new SamplingCase("before initial UTC", 4, 0, 0, 0, 4, false),
                new SamplingCase("after initial UTC", 0, 2, 0, 0, 6, true),
                new SamplingCase("before completion UTC", 0, 0, 2, 0, 4, true),
                new SamplingCase("after completion UTC", 0, 0, 0, 2, 6, true),
                new SamplingCase("after both UTC samples", 0, 1, 0, 1, 6, true),
                new SamplingCase("around both UTC samples", 1, 1, 1, 1, 5, true));

        for (SamplingCase test : cases) {
            MutableClock clock = new MutableClock();
            Instant expires = clock.wallTime.plusSeconds(6);
            long startedNanos = Long.MAX_VALUE - Duration.ofSeconds(2).toNanos();
            clock.elapsedNanos = startedNanos;
            Duration age = Duration.ofHours(8).minusSeconds(6);
            TestDNSProvider.receivedAt = clock.wallTime.minus(age);
            TestDNSProvider.receivedNanos = startedNanos - age.toNanos();
            TestDNSProvider.onLookup = () -> {};
            AtomicInteger reads = new AtomicInteger();
            clock.onRead = () -> {
                // Move time before capturing the UTC value.
                int read = reads.incrementAndGet();
                int seconds = switch (read) {
                    case 1 -> test.initialBefore();
                    case 2 -> test.completionBefore();
                    default -> 0;
                };
                clock.wallTime = clock.wallTime.plusSeconds(seconds);
                clock.elapsedNanos += Duration.ofSeconds(seconds).toNanos();
            };
            clock.afterRead = () -> {
                // Move time after capturing UTC, before the caller samples elapsed time.
                int seconds = switch (reads.get()) {
                    case 1 -> test.initialAfter();
                    case 2 -> test.completionAfter();
                    default -> 0;
                };
                clock.wallTime = clock.wallTime.plusSeconds(seconds);
                clock.elapsedNanos += Duration.ofSeconds(seconds).toNanos();
            };

            try (CAAIssuanceGate gate = timedGate(clock)) {
                Consumer<CAADecision> observer = decision -> {
                    assertEquals(expires, decision.expiresAt(), test.label());
                    assertEquals(startedNanos + Duration.ofSeconds(test.deadlineSeconds()).toNanos(),
                            decision.expiresAtNanos(), test.label());
                };
                if (test.permitted()) {
                    assertEquals("issued", TestCAAIssuance.submit(gate, REQUEST, observer, () -> "issued"), test.label());
                } else {
                    // Four seconds of uncertain sampling exceed the two-second
                    // UTC margin observed at entry, even with normally advancing clocks.
                    var error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                            () -> TestCAAIssuance.submit(gate, REQUEST, observer,
                                    () -> fail("Consumed sampling allowance permitted submission")), test.label());
                    assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED, error.reason(), test.label());
                }
            }
        }
    }

    /**
     * A one-second UTC margin must survive an immediate read, but cannot be
     * renewed by a rollback after sampling consumes it. Give elapsed evidence
     * an hour of remaining life so its age cannot hide a lost UTC allowance.
     */
    @Test
    void rollbackCannotRestoreUtcMarginsConsumedDuringSampling() throws Exception {
        Duration margin = Duration.ofSeconds(1);
        for (boolean initialSample : List.of(true, false)) {
            for (Duration pause : List.of(Duration.ZERO, margin.minusNanos(1), margin, margin.plusSeconds(1))) {
                String scenario = (initialSample ? "initial" : "completion") + " pause " + pause;
                MutableClock clock = new MutableClock();
                Instant started = clock.wallTime;
                long origin = Long.MAX_VALUE - margin.toNanos();
                clock.elapsedNanos = origin;
                TestDNSProvider.receivedAt = initialSample
                        ? started.minus(Duration.ofHours(8)).plus(margin) : started;
                TestDNSProvider.receivedNanos = origin - Duration.ofHours(7).toNanos();
                TestDNSProvider.onLookup = () -> {
                    if (initialSample) {
                        clock.wallTime = clock.wallTime.minusSeconds(3600);
                    }
                };
                AtomicInteger reads = new AtomicInteger();
                clock.onRead = () -> {
                    if (reads.incrementAndGet() == 2 && !initialSample) {
                        clock.wallTime = started.plus(Duration.ofHours(8)).minus(margin);
                    }
                };
                clock.afterRead = () -> {
                    if (reads.get() == (initialSample ? 1 : 2)) {
                        clock.wallTime = clock.wallTime.plus(pause);
                        clock.elapsedNanos += pause.toNanos();
                    }
                };
                Consumer<CAADecision> observer = decision -> {
                    // Hide completion UTC expiry from the gate's later wall read.
                    // The validator must already have preserved the sampled margin.
                    if (!initialSample) {
                        clock.wallTime = clock.wallTime.minusSeconds(3600);
                    }
                };

                try (CAAIssuanceGate gate = timedGate(clock)) {
                    if (pause.compareTo(margin) < 0) {
                        assertEquals("issued", TestCAAIssuance.submit(gate, REQUEST, observer, () -> "issued"), scenario);
                    } else {
                        var error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                                () -> TestCAAIssuance.submit(gate, REQUEST, observer,
                                        () -> fail("Rollback restored a consumed UTC margin")), scenario);
                        assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED, error.reason(), scenario);
                        assertEquals(CAADecision.Reason.EXPIRED, error.decision().names().get(0).reason(), scenario);
                    }
                }
            }
        }
    }

    /** Closing during the last clock read must block an otherwise fresh approval. */
    @Test
    void shutdownDuringFinalElapsedReadBlocksSubmission() throws Exception {
        MutableClock clock = new MutableClock();
        try (CAAIssuanceGate gate = timedGate(clock)) {
            var error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, decision -> clock.onRead = () -> clock.onElapsedRead = gate::close,
                            () -> fail("Submitted after shutdown")));
            assertEquals(CAAIssuanceGate.RejectionReason.CLOSED, error.reason());
            assertEquals(CAADecision.Outcome.ALLOW, error.decision().outcome());
        }
    }

    /** Interruption during the last clock read remains visible to the caller. */
    @Test
    void interruptionDuringFinalElapsedReadBlocksSubmission() throws Exception {
        MutableClock clock = new MutableClock();
        try (CAAIssuanceGate gate = timedGate(clock)) {
            var error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST,
                            decision -> clock.onRead = () -> clock.onElapsedRead = Thread.currentThread()::interrupt,
                            () -> fail("Interrupted caller submitted")));
            assertEquals(CAAIssuanceGate.RejectionReason.CANCELLED, error.reason());
            assertEquals(CAADecision.Outcome.ALLOW, error.decision().outcome());
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
    }

    /**
     * A rollback before entry makes nine-hour-old DNS evidence look seven
     * hours old. Exercise the signed nanoTime rollover in the same interval.
     */
    @Test
    void rollbackBeforeGateEntryCannotReviveExpiredEvidence() throws Exception {
        MutableClock clock = new MutableClock();
        TestDNSProvider.receivedAt = clock.wallTime;
        TestDNSProvider.receivedNanos = Long.MAX_VALUE - Duration.ofHours(1).toNanos();
        clock.wallTime = clock.wallTime.plus(Duration.ofHours(7));
        clock.elapsedNanos = TestDNSProvider.receivedNanos + Duration.ofHours(9).toNanos();

        try (CAAIssuanceGate gate = timedGate(clock)) {
            var error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, decision -> {},
                            () -> fail("Submitted using expired evidence")));
            assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED, error.reason());
            assertEquals(CAADecision.Reason.EXPIRED, error.decision().names().get(0).reason());
        }
    }

    /**
     * Evidence already almost eight hours old has only its remaining minute
     * available to the observer. Starting a gate call must not reset its age.
     */
    @Test
    void elapsedDeadlineAccountsForOlderDnsEvidence() throws Exception {
        MutableClock clock = new MutableClock();
        TestDNSProvider.receivedAt = clock.wallTime.minusSeconds(8 * 3600 - 60);
        TestDNSProvider.receivedNanos = clock.elapsedNanos - Duration.ofHours(8).minusMinutes(1).toNanos();
        // Roll back before entry so the wall clock alone suggests more than a minute.
        clock.wallTime = clock.wallTime.minusSeconds(3600);
        try (CAAIssuanceGate gate = timedGate(clock)) {
            CAAIssuanceGate.CAAApprovalException error = assertThrows(
                    CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, decision -> {
                        assertEquals(CAADecision.Outcome.ALLOW, decision.outcome());
                        assertEquals(TestDNSProvider.receivedAt.plus(Duration.ofHours(8)), decision.expiresAt());
                        clock.wallTime = clock.wallTime.minusSeconds(3600);
                        clock.elapsedNanos += Duration.ofSeconds(61).toNanos();
                    }, () -> fail("Old evidence received a new approval lifetime")));

            assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED, error.reason());
        }
    }

    /**
     * A backward clock adjustment alone leaves a fresh approval usable while
     * both the elapsed allowance and reported expiry still permit submission.
     */
    @Test
    void backwardClockWithinElapsedLifetimeStillAllowsSubmission() throws Exception {
        MutableClock clock = new MutableClock();
        try (CAAIssuanceGate gate = timedGate(clock)) {
            String result = TestCAAIssuance.submit(gate, REQUEST, decision -> {
                clock.wallTime = clock.wallTime.minusSeconds(3600);
                clock.elapsedNanos += Duration.ofMinutes(1).toNanos();
            }, () -> "issued");

            assertEquals("issued", result);
        }
    }

    /**
     * A forward adjustment that passes expiresAt blocks submission even when
     * little monotonic time has elapsed.
     */
    @Test
    void forwardClockPastReportedExpiryBlocksSubmission() throws Exception {
        MutableClock clock = new MutableClock();
        try (CAAIssuanceGate gate = timedGate(clock)) {
            CAAIssuanceGate.CAAApprovalException error = assertThrows(
                    CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, decision -> {
                        clock.wallTime = decision.expiresAt().plusSeconds(1);
                        clock.elapsedNanos += Duration.ofSeconds(1).toNanos();
                    }, () -> fail("Wall-clock expiry ignored")));

            assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED, error.reason());
        }
    }

    /**
     * At entry the wall clock already puts this grant outside its lifetime,
     * even though only seven hours elapsed. A correction during DNS lookup
     * must not give the grant another hour.
     */
    @Test
    void backwardClockDuringLookupCannotReviveOldEvidence() throws Exception {
        MutableClock clock = new MutableClock();
        TestDNSProvider.receivedAt = clock.wallTime.minusSeconds(9 * 3600);
        TestDNSProvider.receivedNanos = clock.elapsedNanos - Duration.ofHours(7).toNanos();
        TestDNSProvider.onLookup = () -> {
            clock.wallTime = clock.wallTime.minusSeconds(2 * 3600);
            clock.elapsedNanos += Duration.ofSeconds(1).toNanos();
        };

        try (CAAIssuanceGate gate = timedGate(clock)) {
            CAAIssuanceGate.CAAApprovalException error = assertThrows(
                    CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, decision -> {},
                            () -> fail("Clock rollback revived old evidence")));

            assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED, error.reason());
            assertEquals(CAADecision.Reason.EXPIRED, error.decision().names().get(0).reason());
        }
    }

    /**
     * Preserve the response timestamp sampled before a forward clock step.
     * Even with only one monotonic second elapsed, wall-clock expiry blocks it.
     */
    @Test
    void forwardClockDuringLookupExpiresEarlierEvidence() throws Exception {
        MutableClock clock = new MutableClock();
        TestDNSProvider.receivedAt = clock.wallTime;
        TestDNSProvider.onLookup = () -> {
            clock.wallTime = clock.wallTime.plusSeconds(9 * 3600);
            clock.elapsedNanos += Duration.ofSeconds(1).toNanos();
        };

        try (CAAIssuanceGate gate = timedGate(clock)) {
            CAAIssuanceGate.CAAApprovalException error = assertThrows(
                    CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, decision -> {},
                            () -> fail("Forward wall-clock expiry ignored")));

            assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED, error.reason());
            assertEquals(CAADecision.Outcome.ERROR, error.decision().outcome());
            assertEquals(CAADecision.Reason.EXPIRED, error.decision().names().get(0).reason());
        }
    }

    /**
     * The fixed maximum age is exclusive at its boundary. Each attempt uses
     * its own fresh evidence; advance only after validation has completed.
     */
    @Test
    void approvalExpiresAtExactlyEightHours() throws Exception {
        Duration maximum = Duration.ofHours(8);
        MutableClock clock = new MutableClock();
        try (CAAIssuanceGate gate = timedGate(clock)) {
            String issued = TestCAAIssuance.submit(gate, REQUEST, decision -> {
                clock.wallTime = clock.wallTime.plus(maximum.minusNanos(1));
                clock.elapsedNanos += maximum.minusNanos(1).toNanos();
            }, () -> "issued");
            assertEquals("issued", issued);

            CAAIssuanceGate.CAAApprovalException error = assertThrows(
                    CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, decision -> {
                        clock.wallTime = clock.wallTime.plus(maximum);
                        clock.elapsedNanos += maximum.toNanos();
                    }, () -> fail("Approval used at its expiry boundary")));
            assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED, error.reason());
        }
    }

    /**
     * Shares wall and monotonic clocks across the real validator, DNS fixture
     * and gate. The controls remain independent so tests can model clock steps
     * during lookup as well as observation, without changing host time.
     */
    private CAAIssuanceGate timedGate(MutableClock clock) {
        CAAPolicy policy = new CAAPolicy(Set.of("ca.example"));
        TestDNSProvider.clock = clock;
        TestDNSProvider.nanoTime = () -> clock.elapsedNanos;
        CAAValidator validator = new DefaultCAAValidator(
                new TestDNSProvider(), policy, clock, () -> clock.elapsedNanos);
        return new CAAIssuanceGate(validator, clock, clock::readElapsed);
    }

    /**
     * Keeps wall time independent of elapsed time to model host-clock corrections.
     */
    private static final class MutableClock extends Clock {
        Instant wallTime = Instant.parse("2026-11-23T12:00:00Z");
        long elapsedNanos;
        Runnable onRead = () -> {};
        Runnable afterRead = () -> {};
        Runnable onElapsedRead = () -> {};

        long readElapsed() {
            onElapsedRead.run();
            return elapsedNanos;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return Clock.fixed(wallTime, zone);
        }

        @Override
        public Instant instant() {
            onRead.run();
            Instant sampled = wallTime;
            afterRead.run();
            return sampled;
        }
    }

    /**
     * Return DNS evidence received nine hours ago. Evaluation must report
     * expiry to the observer, and the gate must block the submission callback.
     */
    @Test
    void expiredEvidenceIsObservedButCannotReachTheIssuer() throws Exception {
        TestDNSProvider.receivedNanos = System.nanoTime() - Duration.ofHours(9).toNanos();
        TestDNSProvider.receivedAt = Instant.now().minusSeconds(9 * 3600);

        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            AtomicInteger observations = new AtomicInteger();
            AtomicReference<CAADecision> observed = new AtomicReference<>();

            CAAIssuanceGate.CAAApprovalException error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST,
                            decision -> {
                                observations.incrementAndGet();
                                observed.set(decision);
                            },
                            () -> fail("Expired decision submitted")));
            assertEquals(CAADecision.Outcome.ERROR, error.decision().outcome());
            assertEquals(CAADecision.Reason.EXPIRED, error.decision().names().get(0).reason());
            assertEquals(CAAIssuanceGate.RejectionReason.EXPIRED, error.reason());
            assertEquals(1, observations.get());
            assertSame(error.decision(), observed.get());
        }
    }

    /**
     * Old evidence may deny policy without approving any name. Age both that
     * denial and a DNS failure past the gate deadline. Their evaluation reasons
     * must survive, and neither may reach the issuer.
     */
    @Test
    void staleDenialsAndDnsFailuresRemainEvaluationRejections() throws Exception {
        Duration age = Duration.ofHours(9);
        for (boolean dnsFailure : List.of(false, true)) {
            MutableClock clock = new MutableClock();
            TestDNSProvider.issuer = ";";
            TestDNSProvider.error = dnsFailure;
            TestDNSProvider.receivedAt = clock.wallTime.minus(age);
            TestDNSProvider.receivedNanos = clock.elapsedNanos - age.toNanos();

            try (CAAIssuanceGate gate = timedGate(clock)) {
                CAAIssuanceGate.CAAApprovalException error = assertThrows(
                        CAAIssuanceGate.CAAApprovalException.class,
                        () -> TestCAAIssuance.submit(gate, REQUEST, decision -> {
                            // Also expire failures that carry no successful DNS observations.
                            clock.wallTime = clock.wallTime.plus(age);
                            clock.elapsedNanos += age.toNanos();
                        }, () -> fail("Rejected evaluation reached the issuer")));

                assertEquals(CAAIssuanceGate.RejectionReason.EVALUATION, error.reason());
                assertEquals(dnsFailure ? CAADecision.Outcome.ERROR : CAADecision.Outcome.DENY,
                        error.decision().outcome());
                assertEquals(dnsFailure ? CAADecision.Reason.DNS_FAILURE : CAADecision.Reason.ISSUER_NOT_AUTHORIZED,
                        error.decision().names().get(0).reason());
            }
        }
    }

    /**
     * Close the gate from its observer after an ALLOW evaluation. The final
     * gate check must reject submission; repeated close calls must close DNS only once.
     */
    @Test
    void closeDuringObservationBlocksSubmissionAndClosesTheClientOnce() throws Exception {
        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            CAAIssuanceGate.CAAApprovalException error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST,
                            decision -> gate.close(), () -> fail("Closed gate submitted")));

            assertEquals(CAADecision.Outcome.ALLOW, error.decision().outcome());
            assertEquals(CAAIssuanceGate.RejectionReason.CLOSED, error.reason());
            gate.close();

            assertEquals(1, TestDNSProvider.closes.get());
        }
        assertEquals(1, TestDNSProvider.closes.get());
    }

    /**
     * Close a disabled gate, then try submission. Even a disabled gate must
     * reject use after shutdown instead of bypassing its lifecycle checks.
     */
    @Test
    void closingADisabledGateDoesNotEnableAnIssuanceBypass() throws Exception {
        try (CAAIssuanceGate gate = CAAIssuanceGate.open(new Properties(), getClass().getClassLoader())) {
            gate.close();

            assertThrows(IllegalStateException.class,
                    () -> TestCAAIssuance.submit(gate, null,
                            decision -> fail("Closed gate observed CAA"),
                            () -> fail("Closed disabled gate submitted")));
        }
    }

    /**
     * No enabled setting means no CAA check and no provider allocation.
     */
    @Test
    void configurationDefaultsOff() throws Exception {
        Properties properties = new Properties();

        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties, getClass().getClassLoader())) {
            gate.check(null, decision -> fail("Disabled gate checked CAA"));

            assertFalse(gate.isEnabled());
            assertEquals(0, TestDNSProvider.opens.get());
        }
    }

    /**
     * A misspelled enabled value must fail before a DNS provider is opened.
     */
    @Test
    void invalidEnabledValueFailsConfiguration() {
        Properties properties = properties();
        properties.setProperty("enabled", "ture");

        DNSLookupException failure = assertThrows(DNSLookupException.class,
                () -> CAAIssuanceGate.open(properties, getClass().getClassLoader()));
        assertEquals(DNSLookupException.Reason.CONFIGURATION, failure.failure().reason());
        assertEquals(0, TestDNSProvider.opens.get());
    }

    /**
     * Explicit enablement must fail when the selected provider is not installed.
     */
    @Test
    void enabledWithMissingProviderFailsConfiguration() {
        Properties properties = properties();
        properties.setProperty("dns.class", "missing.Adapter");

        DNSLookupException failure = assertThrows(DNSLookupException.class,
                () -> CAAIssuanceGate.open(properties, getClass().getClassLoader()));
        assertEquals(DNSLookupException.Reason.CONFIGURATION, failure.failure().reason());
        assertEquals(0, TestDNSProvider.opens.get());
    }

    /**
     * Change the fixture from grant to denial to DNS error between attempts.
     * Every attempt must consult DNS, and only the grant can invoke the issuer.
     */
    @Test
    void submissionRequiresAllowWithoutCachingAcrossRequests() throws Exception {
        AtomicInteger submissions = new AtomicInteger();
        Consumer<CAADecision> observer = decision -> {
            // This test checks admission, not the contents of logged decisions.
        };

        try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
            int submitted = TestCAAIssuance.submit(gate, REQUEST, observer, submissions::incrementAndGet);

            assertEquals(1, submitted);

            TestDNSProvider.issuer = ";";

            CAAIssuanceGate.CAAApprovalException denial = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, observer, submissions::incrementAndGet));
            assertEquals(CAADecision.Outcome.DENY, denial.decision().outcome());
            assertEquals(CAAIssuanceGate.RejectionReason.EVALUATION, denial.reason());

            TestDNSProvider.error = true;

            CAAIssuanceGate.CAAApprovalException failure = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, observer, submissions::incrementAndGet));
            assertEquals(CAADecision.Outcome.ERROR, failure.decision().outcome());
            assertEquals(CAAIssuanceGate.RejectionReason.EVALUATION, failure.reason());
            assertEquals(1, submissions.get());
            assertEquals(3, TestDNSProvider.lookups.get());
            gate.close();

            assertThrows(IllegalStateException.class,
                    () -> TestCAAIssuance.submit(gate, REQUEST, observer, submissions::incrementAndGet));
            assertEquals(1, submissions.get());
        }
    }

    /**
     * Untrusted grants and apparent absence must both stop at the gate. Either
     * response could hide restrictions; neither may reach issuer submission.
     */
    @Test
    void missingAssuranceBlocksSubmissionForGrantsAndAbsence() throws Exception {
        for (boolean absent : List.of(false, true)) {
            TestDNSProvider.untrusted = true;
            TestDNSProvider.absent = absent;
            TestDNSProvider.lookups.set(0);
            AtomicInteger submissions = new AtomicInteger();
            try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties(), getClass().getClassLoader())) {
                CAAIssuanceGate.CAAApprovalException failure = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                        () -> TestCAAIssuance.submit(gate, REQUEST, decision -> {}, submissions::incrementAndGet));

                String scenario = absent ? "absence" : "grant";
                assertEquals(CAADecision.Outcome.ERROR, failure.decision().outcome(), scenario);
                assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE,
                        failure.decision().names().get(0).failure().orElseThrow().reason(), scenario);
                assertEquals(0, submissions.get(), scenario);
                assertEquals(1, TestDNSProvider.lookups.get(), scenario);
            }
        }
    }

    private Properties properties() {
        Properties properties = new Properties();
        properties.setProperty("enabled", "true");
        properties.setProperty("issuerIdentifiers", "ca.example");
        properties.setProperty("dns.class", TestDNSProvider.class.getName());
        return properties;
    }

    /**
     * Public no-argument provider for class-name loading. Each test resets its
     * policy, timestamps and counters. No real DNS traffic occurs.
     */
    public static final class TestDNSProvider implements CAADNSClientProvider, CAADNSClient {
        static final AtomicInteger opens = new AtomicInteger();
        static final AtomicInteger closes = new AtomicInteger();
        static final AtomicInteger lookups = new AtomicInteger();
        static Map<String, String> settings;
        static String issuer;
        static Instant receivedAt;
        static Clock clock;
        static LongSupplier nanoTime;
        static long receivedNanos;
        static Runnable onLookup;
        static boolean error;
        static boolean untrusted;
        static boolean absent;

        @Override
        public CAADNSClient open(Config config) {
            opens.incrementAndGet();
            settings = config.settings();
            return this;
        }

        @Override
        public LookupResult resolveCaa(DNSDomainName candidate, LookupBudget budget) throws DNSLookupException {
            budget.reserveQuery();
            lookups.incrementAndGet();
            onLookup.run();
            if (error) {
                throw DefaultCAAValidator.failure(DNSLookupException.Reason.UNREACHABLE, "Fixture DNS unavailable");
            }
            CAARecord record = new CAARecord(candidate, 60, 0, "issue", issuer.getBytes(StandardCharsets.US_ASCII));
            ValidationStatus status = untrusted ? ValidationStatus.UNTRUSTED : ValidationStatus.UNCLASSIFIED;
            ResponseEvidence response = new ResponseEvidence("fixture", candidate, 0, false,
                    status, receivedAt == null ? nanoTime.getAsLong() : receivedNanos,
                    receivedAt == null ? clock.instant() : receivedAt, "fixture", Optional.empty());
            LookupKind kind = absent ? LookupKind.NODATA : LookupKind.RRSET;
            List<CAARecord> records = absent ? List.of() : List.of(record);
            return new LookupResult(candidate, candidate, kind,
                    records, List.of(), List.of(response), Optional.empty());
        }

        @Override
        public void close() {
            closes.incrementAndGet();
        }
    }
}
