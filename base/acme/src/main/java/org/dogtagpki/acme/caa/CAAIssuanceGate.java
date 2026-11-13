// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.io.PrintWriter;
import java.io.Writer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.stream.Collectors;

/**
 * Connects CAA evaluation to the consuming subsystem's issuance sequence.
 * The host calls check() before submitting a certificate request to its issuer;
 * the gate evaluates policy and refuses submission when approval is unusable.
 * It does not invoke the issuer or update enrollment/order state.
 *
 * Configuration and ownership:
 * - open() accepts trusted host properties and a class loader. It does not read
 *   a configuration file or retain the properties for dynamic reload.
 * - enabled defaults to false. A disabled gate opens no DNS provider and skips
 *   validation; returning normally in this mode is not a CAA authorization.
 * - When enabled, issuerIdentifiers defines the intended authority's policy,
 *   dns.class selects its DNS provider, and dns.settings.* configures that provider.
 *   The provider must establish trusted DNSSEC enforcement. Initialization
 *   failures propagate instead of disabling checking.
 * - Reuse one gate for an issuer policy. It owns the validator and DNS client;
 *   the host closes the gate at shutdown, not after each enrollment request.
 *
 * Evaluation and submission:
 * - check() sends the decision to the observer, then checks shutdown,
 *   interruption, outcome and approval freshness. An observed ALLOW can still
 *   be blocked by those checks or an observer exception.
 * - Observers run on calling threads and must support concurrent requests.
 * - The host maps refusals into its protocol's response and submits only after
 *   check() returns normally. It must preserve the checked names, issuer policy
 *   and decision freshness through actual signing.
 */
public final class CAAIssuanceGate implements AutoCloseable {
    private final CAAValidator validator;
    private final Clock clock;
    private final LongSupplier nanoTime;
    private final AtomicBoolean closed = new AtomicBoolean();

    private CAAIssuanceGate(CAAValidator validator) {
        this(validator, Clock.systemUTC(), System::nanoTime);
    }

    /**
     * Supplies wall and monotonic clocks for deterministic lifetime tests.
     * Production gates use the system clocks and the fixed policy age limit.
     */
    CAAIssuanceGate(CAAValidator validator, Clock clock, LongSupplier nanoTime) {
        this.validator = validator;
        this.clock = clock;
        this.nanoTime = nanoTime;
    }

    /**
     * Disabled by default, including when upgrading an instance without caa.conf.
     */
    public static CAAIssuanceGate open(Properties properties, ClassLoader loader) throws DNSLookupException {
        validatePropertyTypes(properties);
        Set<String> keys = Set.of("enabled", "issuerIdentifiers", "dns.class");
        for (String key : properties.stringPropertyNames()) {
            if (!keys.contains(key) && !key.startsWith("dns.settings.")) {
                throw DefaultCAAValidator.failure(DNSLookupException.Reason.CONFIGURATION, "Unknown CAA setting");
            }
        }

        String enabled = properties.getProperty("enabled", "false").strip();
        if (!Set.of("true", "false").contains(enabled)) {
            throw DefaultCAAValidator.failure(DNSLookupException.Reason.CONFIGURATION, "CAA enabled must be true or false");
        }

        if (enabled.equals("false")) {
            return new CAAIssuanceGate(null);
        }

        CAAPolicy policy;

        try {
            policy = new CAAPolicy(Arrays.stream(properties.getProperty("issuerIdentifiers", "").split(",", -1))
                    .map(String::strip).collect(Collectors.toSet()));
        } catch (IllegalArgumentException e) {
            throw DefaultCAAValidator.failure(DNSLookupException.Reason.CONFIGURATION, "Invalid CAA issuer identifiers");
        }

        var settings = new HashMap<String, String>();
        for (String key : properties.stringPropertyNames()) {
            if (key.startsWith("dns.settings.")) {
                settings.put(key.substring(13), properties.getProperty(key));
            }
        }

        CAADNSClient client = CAADNSClientLoader.open(properties.getProperty("dns.class", ""), loader,
                new CAADNSClientProvider.Config(settings));
        return new CAAIssuanceGate(new DefaultCAAValidator(client, policy));
    }

    public boolean isEnabled() {
        return validator != null;
    }

    /**
     * Rejects malformed programmatic settings before defaults can disable CAA.
     * Check explicit entries, then the effective inherited key/value pairs.
     * String-only accessors can skip a malformed inherited value and fall back
     * to a deeper default, silently disabling enforcement.
     */
    private static void validatePropertyTypes(Properties properties) throws DNSLookupException {
        for (var entry : properties.entrySet()) {
            if (!(entry.getKey() instanceof String) || !(entry.getValue() instanceof String)) {
                throw DefaultCAAValidator.failure(DNSLookupException.Reason.CONFIGURATION,
                        "CAA settings must be strings");
            }
        }
        try {
            // list() checks effective values in the defaults chain as strings.
            // propertyNames() exposes only keys, while getProperty() skips
            // non-string values. Discard output so no settings are logged.
            properties.list(new PrintWriter(Writer.nullWriter()));
        } catch (ClassCastException e) {
            // Properties throws for an effective non-string key or value.
            throw DefaultCAAValidator.failure(DNSLookupException.Reason.CONFIGURATION,
                    "CAA settings must be strings");
        }
    }

    /**
     * Returns after an unexpired approval, or when CAA is disabled.
     *
     * - Observers run on the calling threads and may run concurrently.
     * - The observer receives evaluation evidence before the final gate check.
     *   The host records submission approval separately.
     * - With CAA enabled, observer failure or caller interruption blocks submission.
     *   With CAA disabled, the host handles interruption and cancellation. The
     *   gate leaves the interrupt flag intact and invokes neither DNS nor observer.
     * - Both wall-clock expiry and monotonic elapsed lifetime must permit submission.
     * - UTC and monotonic clocks are sampled separately. A forward UTC adjustment
     *   after the wall-clock read can go undetected. The monotonic deadline still
     *   bounds elapsed decision age. The host must preserve names, policy and
     *   freshness through signing.
     */
    public void check(CAARequest request, Consumer<CAADecision> observer) throws CAAApprovalException {
        if (closed.get()) {
            throw new IllegalStateException("CAA issuance gate is closed");
        }
        if (validator != null) {
            CAADecision decision = validator.validate(request);
            observer.accept(decision);

            // Bracket the UTC read with elapsed samples. Charge the whole
            // interval against its observed UTC margin, including a thread
            // pause between reading UTC and taking the final elapsed sample.
            long beforeWall = nanoTime.getAsLong();
            Instant now = clock.instant();
            long nowNanos = nanoTime.getAsLong();
            long samplingNanos = nowNanos - beforeWall;
            Duration wallRemaining = Duration.between(now, decision.expiresAt());

            // These are the final cooperative admission checks. The host owns
            // cancellation and signing once control returns to it.
            if (closed.get()) {
                throw new CAAApprovalException(decision, RejectionReason.CLOSED);
            }

            // An observer can leave the caller interrupted after validation.
            // Preserve that flag and refuse the handoff just as DNS work does.
            if (Thread.currentThread().isInterrupted()) {
                throw new CAAApprovalException(decision, RejectionReason.CANCELLED);
            }

            // Preserve the evaluation reason when no approval was available.
            // An approval invalidated by the validator still reports expiry.
            if (decision.outcome() != CAADecision.Outcome.ALLOW) {
                boolean expiredApproval = decision.names().stream()
                        .anyMatch(name -> name.reason() == CAADecision.Reason.EXPIRED);
                throw new CAAApprovalException(decision,
                        expiredApproval ? RejectionReason.EXPIRED : RejectionReason.EVALUATION);
            }

            if (samplingNanos < 0 || nowNanos - decision.expiresAtNanos() >= 0
                    || wallRemaining.compareTo(Duration.ofNanos(samplingNanos)) <= 0) {
                throw new CAAApprovalException(decision, RejectionReason.EXPIRED);
            }
        }
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true) && validator != null) validator.close();
    }

    /**
     * Separates evaluation failure from expiry, cancellation or shutdown.
     */
    public enum RejectionReason {
        // The validator returned DENY or ERROR; inspect its per-name reasons.
        EVALUATION,

        // The decision expired before submission, even if evaluation returned ALLOW.
        EXPIRED,

        // The caller was interrupted before permission to submit was returned.
        CANCELLED,

        // The gate closed after evaluation and blocked submission.
        CLOSED
    }

    /**
     * Reports why the gate refused submission, retaining the evaluation decision.
     * The consuming subsystem maps this refusal into its protocol's error response.
     * A decision may say ALLOW while expiry, cancellation or shutdown blocks handoff.
     */
    public static final class CAAApprovalException extends Exception {
        private static final long serialVersionUID = 1L;
        private final CAADecision decision;
        private final RejectionReason reason;

        CAAApprovalException(CAADecision decision, RejectionReason reason) {
            super("CAA authorization did not permit issuance");
            this.decision = decision;
            this.reason = reason;
        }

        public CAADecision decision() {
            return decision;
        }
        public RejectionReason reason() {
            return reason;
        }
    }
}
