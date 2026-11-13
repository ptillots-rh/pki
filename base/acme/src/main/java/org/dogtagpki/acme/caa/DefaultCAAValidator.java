// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;

import org.dogtagpki.acme.caa.CAADNSClient.LookupResult;
import org.dogtagpki.acme.caa.CAADecision.NameDecision;
import org.dogtagpki.acme.caa.CAADecision.Outcome;
import org.dogtagpki.acme.caa.CAADecision.Reason;

/**
 * Discovers and evaluates CAA policy for all DNS names in one issuance request.
 * The consuming subsystem supplies the intended certificate names and trusted
 * binding context; this implementation combines DNS observations with its
 * configured issuer policy to return a CAADecision.
 *
 * Responsibilities:
 * - The DNS client resolves one candidate through aliases. This validator finds
 *   the relevant RRset by walking the original candidate's parents on absence.
 * - The discovered policy is evaluated separately for each name, including
 *   wildcard status and account/method restrictions. Every name must allow.
 * - One Budget bounds the entire attempt. A semaphore separately limits the
 *   number of concurrent attempts; admission rejects rather than queues.
 * - DNS observations are reused within an attempt, never across requests.
 *   A DNS failure becomes an ERROR decision, not permission based on absence.
 *
 * Lifecycle
 * The subsystem creates a long-lived validator with a DNS client and immutable
 * CAAPolicy, then closes it at shutdown. The validator owns and closes the client.
 *
 * DNS trust
 * Provider selection and DNSSEC enforcement belong to the DNS layer. RFC 8657
 * Section 5.6 requires trusted DNSSEC validation because a forged answer can
 * remove binding parameters entirely. All discovery evidence must have trusted
 * assurance, including records without parameters and established absence.
 *
 * Submission
 * The consuming subsystem submits certificates and preserves the checked names,
 * issuer policy and decision freshness through signing.
 */
public final class DefaultCAAValidator implements CAAValidator {
    private final CAADNSClient client;
    private final CAAPolicy policy;
    private final Semaphore checks;
    private final Clock clock;
    private final LongSupplier nanoTime;
    private final AtomicBoolean closed = new AtomicBoolean();

    /**
     * Creates a validator using the system UTC clock.
     *
     * Parameters:
     * - client supplies trusted DNS discovery evidence and must support concurrent
     *   lookups. The validator owns this client and closes it during shutdown.
     * - policy supplies the accepted issuer identifiers, resource limits and
     *   maximum decision age. It applies to every attempt on this instance.
     *
     * Both parameters are required. The caller retains the validator across
     * issuance attempts and closes it when the consuming subsystem shuts down.
     */
    public DefaultCAAValidator(CAADNSClient client, CAAPolicy policy) {
        this(client, policy, Clock.systemUTC());
    }

    /**
     * Creates a validator with an explicit clock for deterministic timing tests.
     *
     * Parameters:
     * - client supplies trusted DNS discovery evidence for concurrent attempts.
     *   The validator owns the client and closes it during shutdown.
     * - policy supplies the accepted issuer identifiers, resource limits and
     *   maximum decision age for this instance.
     * - clock supplies wall-clock start and completion timestamps, including the
     *   completion time used to cap decision expiry. Tests can control this clock
     *   to pause completion or model a host-clock adjustment.
     *
     * All parameters are required. DNS response timestamps come from the client.
     * Resource deadlines use monotonic elapsed time in Budget independently of
     * this clock.
     */
    DefaultCAAValidator(CAADNSClient client, CAAPolicy policy, Clock clock) {
        this(client, policy, clock, System::nanoTime);
    }

    /**
     * Supplies both clocks for tests that advance completion past the deadline.
     *
     * Parameters:
     * - client supplies concurrent trusted DNS lookups and is owned by this validator.
     * - policy supplies issuer identifiers, resource limits and maximum decision age.
     * - clock supplies wall-clock start and completion timestamps.
     * - nanoTime supplies monotonic nanoseconds for each attempt's resource budget.
     *
     * All parameters are required. Tests can share these clocks with the gate
     * and DNS fixture without sleeping or changing the host's system time.
     */
    DefaultCAAValidator(CAADNSClient client, CAAPolicy policy, Clock clock, LongSupplier nanoTime) {
        this.clock = java.util.Objects.requireNonNull(clock);
        this.nanoTime = java.util.Objects.requireNonNull(nanoTime);
        this.client = java.util.Objects.requireNonNull(client);
        this.policy = java.util.Objects.requireNonNull(policy);
        checks = new Semaphore(policy.limits().maxConcurrentChecks());
    }

    /**
     * Discovers policy for each name, then combines the per-name decisions.
     * DNS observations are reused only within this attempt; wildcard and binding
     * rules are evaluated separately for each certificate name. Continue after
     * a name fails so the result describes every requested name.
     *
     * Certificate name
     *       |
     *       v
     * Resolve candidate, following aliases
     *       |
     *       +-- DNS failure ----------> ERROR
     *       |
     *       +-- CAA RRset ------------> Evaluate policy
     *       |
     *       +-- Established absence
     *                 |
     *                 v
     *        Original candidate's parent
     *                 |
     *                 +-- Not root --> Repeat lookup
     *                 |
     *                 +-- Root ------> No restriction
     */
    @Override
    public CAADecision validate(CAARequest request) {
        // One resource budget covers the entire attempt, including all names,
        // parent lookups and alias traversal, starting before wall-clock reads.
        // Starting another name does not reset it.
        Budget budget = new Budget(policy.limits(), nanoTime);
        ClockSample started = sampleClocks();
        List<NameDecision> decisions = new ArrayList<>();
        Map<DNSDomainName, LookupResult> observations = new HashMap<>();

        boolean admitted = !closed.get() && checks.tryAcquire();
        try {
            for (CAARequest.CertificateName name : request.names()) {
                List<LookupResult> discovery = new ArrayList<>();
                Optional<DNSDomainName> owner = Optional.empty();

                try {
                    if (!admitted || closed.get()) {
                        throw failure(closed.get() ? DNSLookupException.Reason.CANCELLED
                                : DNSLookupException.Reason.LIMIT_EXCEEDED, "CAA checker unavailable");
                    }

                    DNSDomainName candidate = name.baseName();
                    Reason reason = Reason.NO_RESTRICTION;
                    while (!candidate.asciiAbsoluteName().equals(".")) {
                        // Stop on interruption or the total lookup deadline, even
                        // when this candidate reuses an observation from this attempt.
                        // The DNS client charges actual queries and alias transitions.
                        budget.check();
                        LookupResult result = observations.get(candidate);
                        if (result == null) {
                            result = client.resolveCaa(candidate, budget);
                            verifyAssurance(candidate, result);
                            observations.put(candidate, result);
                        }

                        discovery.add(result);

                        if (result.kind() == CAADNSClient.LookupKind.RRSET) {
                            owner = Optional.of(result.terminalName());
                            reason = evaluate(result.records(), name, request.contexts().get(name));
                            break;
                        }

                        // RFC 8659 Section 3: climb the original candidate, never an alias target.
                        String original = candidate.asciiAbsoluteName();
                        String parent = original.substring(original.indexOf('.') + 1);
                        candidate = new DNSDomainName(parent.isEmpty() ? "." : parent);
                    }

                    // A lookup or policy evaluation may have used the remaining
                    // time. Check again before accepting this name's outcome.
                    budget.check();
                    Outcome outcome = reason == Reason.NO_RESTRICTION || reason == Reason.ISSUER_AUTHORIZED
                            ? Outcome.ALLOW : Outcome.DENY;
                    decisions.add(new NameDecision(name, outcome, reason, owner, discovery, Optional.empty()));
                } catch (DNSLookupException e) {
                    decisions.add(new NameDecision(name, Outcome.ERROR, Reason.DNS_FAILURE,
                            owner, discovery, Optional.of(e.failure())));
                }
            }

            ClockSample completion = sampleClocks();
            Instant finished = completion.utc();
            Deadline deadline = deadline(observations.values(), started, budget.started, completion);
            // Retain the evaluated results until final admission. Shutdown
            // must take precedence if it overlaps expiry during construction.
            List<NameDecision> completedNames = decisions;
            if (closed.get()) {
                var cancelled = failure(DNSLookupException.Reason.CANCELLED, "CAA checker closed").failure();
                completedNames = invalidateApprovals(decisions, Reason.DNS_FAILURE, Optional.of(cancelled));
            } else if (!deadline.wallTime().isAfter(finished)) {
                completedNames = invalidateApprovals(decisions, Reason.EXPIRED, Optional.empty());
            }
            CAADecision completed = new CAADecision(CAADecision.aggregateOutcome(completedNames), completedNames,
                    finished, deadline.wallTime(), deadline.nanoTime());

            // Hold the permit through decision construction. A timeout, shutdown
            // or expiry here invalidates only the names still permitting issuance.
            try {
                long now = budget.check();
                if (closed.get()) {
                    throw failure(DNSLookupException.Reason.CANCELLED, "CAA checker closed");
                }
                if (now - deadline.nanoTime() < 0 || !deadline.wallTime().isAfter(finished)) {
                    return completed;
                }
                decisions = invalidateApprovals(decisions, Reason.EXPIRED, Optional.empty());
            } catch (DNSLookupException e) {
                // The final elapsed read can both exhaust the budget and close
                // the validator. Shutdown retains precedence in that interval.
                var failure = closed.get()
                        ? failure(DNSLookupException.Reason.CANCELLED, "CAA checker closed").failure()
                        : e.failure();
                decisions = invalidateApprovals(decisions, Reason.DNS_FAILURE, Optional.of(failure));
            }
            return new CAADecision(CAADecision.aggregateOutcome(decisions), decisions,
                    finished, deadline.wallTime(), deadline.nanoTime());
        } finally {
            if (admitted) {
                checks.release();
            }
        }
    }

    private record Deadline(Instant wallTime, long nanoTime) {}

    private record ClockSample(Instant utc, long beforeNanos, long afterNanos) {}

    /**
     * UTC is captured somewhere between the elapsed readings. Its exact capture
     * point is unavailable, so reserve any UTC allowance from the earlier tick.
     * A sampling pause can conservatively exhaust a nearly expired allowance.
     */
    private ClockSample sampleClocks() {
        long before = nanoTime.getAsLong();
        Instant utc = clock.instant();
        return new ClockSample(utc, before, nanoTime.getAsLong());
    }

    /**
     * Preserve each observed UTC allowance and the original elapsed evidence age.
     * The earlier edge of each sampling bracket prevents a later rollback from
     * restoring time spent after UTC was captured. Take the minimum of these
     * independent limits instead of repeatedly translating one into another.
     */
    private Deadline deadline(Collection<LookupResult> observations, ClockSample started,
            long attemptStartedNanos, ClockSample finished) {
        long now = finished.afterNanos();
        long maxAge = policy.maxDecisionAge().toNanos();
        long remaining = remainingLifetime(attemptStartedNanos, now, maxAge);
        Instant oldest = observations.isEmpty() ? started.utc() : finished.utc();
        for (LookupResult lookup : observations) {
            for (var response : lookup.responses()) {
                if (response.receivedAt().isBefore(oldest)) {
                    oldest = response.receivedAt();
                }
                remaining = Math.min(remaining, remainingLifetime(response.receivedNanos(), now, maxAge));
            }
        }

        Instant expires = oldest.plus(policy.maxDecisionAge());
        remaining = Math.min(remaining, remainingWallAllowance(started, expires, now));
        remaining = Math.min(remaining, remainingWallAllowance(finished, expires, now));
        return new Deadline(expires, now + remaining);
    }

    /** Charges each UTC margin from the earliest possible capture time. */
    private long remainingWallAllowance(ClockSample sample, Instant expires, long now) {
        Duration margin = Duration.between(sample.utc(), expires);
        if (margin.isNegative() || margin.isZero()) {
            return 0;
        }
        Duration maximum = policy.maxDecisionAge();
        long allowance = margin.compareTo(maximum) > 0 ? maximum.toNanos() : margin.toNanos();
        return remainingLifetime(sample.beforeNanos(), now, allowance);
    }

    private static long remainingLifetime(long received, long now, long maxAge) {
        long age = now - received;
        return age < 0 || age >= maxAge ? 0 : maxAge - age;
    }

    /**
     * Invalidates pending approvals without replacing prior denials or errors.
     * Keep each name's selected owner and discovery evidence for diagnostics.
     */
    private static List<NameDecision> invalidateApprovals(List<NameDecision> decisions, Reason reason,
            Optional<DNSLookupException.Failure> failure) {
        List<NameDecision> invalidated = new ArrayList<>();
        for (NameDecision decision : decisions) {
            if (decision.outcome() == Outcome.ALLOW) {
                invalidated.add(new NameDecision(decision.name(), Outcome.ERROR, reason,
                        decision.relevantOwner(), decision.discovery(), failure));
            } else {
                invalidated.add(decision);
            }
        }
        return invalidated;
    }

    /**
     * Rejects discovery without trusted DNSSEC assurance before policy evaluation.
     * This applies to every response, including alias steps and absence: checking
     * only parameter-bearing CAA records would allow stripped binding restrictions.
     */
    private void verifyAssurance(DNSDomainName candidate, LookupResult result) throws DNSLookupException {
        if (!candidate.equals(result.candidate())) {
            throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE, "CAA candidate mismatch");
        }

        for (var response : result.responses()) {
            // Require an explicit trust decision when a new status is added.
            boolean trusted = switch (response.validationStatus()) {
                case SECURE, UNCLASSIFIED -> true;
                case UNTRUSTED -> false;
            };
            if (!trusted) {
                throw new DNSLookupException(new DNSLookupException.Failure(
                        DNSLookupException.Reason.VALIDATION_FAILURE, "Missing required DNS assurance",
                        List.of(response)));
            }
        }
    }

    /**
     * Evaluates the first discovered RRset. For wildcards, any issuewild record
     * takes precedence over all issue records. An RRset containing only iodef
     * or other non-applicable properties stops discovery without restricting
     * issuance. Applicable grants are additive: one passing grant is sufficient.
     *
     * Unrecognized property with critical flag set? -- yes --> DENY
     *           |
     *           no
     *           v
     * Wildcard and issuewild present?
     *           |
     *           +-- yes --> Evaluate issuewild records
     *           |
     *           +-- no ---> Evaluate issue records
     *                               |
     *                               +-- None applicable --> No restriction
     *                               |
     *                               +-- Any grant passes -> Authorized
     *                               |
     *                               +-- No grant passes --> DENY
     */
    private Reason evaluate(List<CAADNSClient.CAARecord> records, CAARequest.CertificateName name,
            CAARequest.IssuanceContext context) {
        // iodef is recognized as a reporting destination. Recognizing this
        // property does not require dispatching reports, even when critical.
        Set<String> known = Set.of("issue", "issuewild", "iodef");

        // RFC 8659 Section 4.5: an unrecognized critical property blocks issuance.
        for (var record : records) {
            if ((record.flags() & 128) != 0 && !known.contains(record.tag().toLowerCase(Locale.ROOT))) {
                return Reason.UNKNOWN_CRITICAL_PROPERTY;
            }
        }

        // RFC 8659 Section 4.3: issuewild overrides issue for wildcard names.
        boolean wildcardPolicy = name.wildcard()
                && records.stream().anyMatch(r -> r.tag().equalsIgnoreCase("issuewild"));
        String tag = wildcardPolicy ? "issuewild" : "issue";
        List<CAADNSClient.CAARecord> applicable = records.stream()
                .filter(r -> r.tag().equalsIgnoreCase(tag)).toList();

        if (applicable.isEmpty()) {
            return Reason.NO_RESTRICTION;
        }

        // RFC 8659 Section 4.2: applicable records grant independently.
        Reason denied = Reason.ISSUER_NOT_AUTHORIZED;
        for (var record : applicable) {
            Reason result = grant(record.value(), context);
            if (result == Reason.ISSUER_AUTHORIZED) {
                return result;
            }
            if (result != Reason.ISSUER_NOT_AUTHORIZED) {
                denied = result;
            }
        }

        return denied;
    }

    /**
     * A malformed or unsatisfied property grants nothing; another property may
     * grant. Unknown or duplicate parameters conservatively reject this grant
     * rather than ignoring a possible restriction or choosing an ambiguous value.
     * Issuer matching ignores case; account URI matching preserves the exact
     * string supplied in the trusted issuance context.
     */
    private Reason grant(byte[] bytes, CAARequest.IssuanceContext context) {
        for (byte b : bytes) {
            int value = Byte.toUnsignedInt(b);
            if (value > 126 || (value < 32 && value != 9)) {
                return Reason.ISSUER_NOT_AUTHORIZED;
            }
        }

        String[] parts = new String(bytes, StandardCharsets.US_ASCII).split(";", -1);
        String issuer = parts[0].strip();
        try {
            CAAPolicy.validateIssuerIdentifier(issuer);
        } catch (IllegalArgumentException e) {
            return Reason.ISSUER_NOT_AUTHORIZED;
        }

        if (policy.issuerIdentifiers().stream().noneMatch(issuer::equalsIgnoreCase)) {
            return Reason.ISSUER_NOT_AUTHORIZED;
        }

        Map<String, String> parameters = new HashMap<>();
        for (int i = 1; i < parts.length; i++) {
            String part = parts[i].strip();
            if (part.isEmpty() && parts.length == 2) continue;

            int separator = part.indexOf('=');
            if (separator < 0) {
                return Reason.ISSUER_NOT_AUTHORIZED;
            }

            String key = part.substring(0, separator).stripTrailing();
            String value = part.substring(separator + 1).stripLeading();
            if (!validParameterTag(key)) {
                return Reason.ISSUER_NOT_AUTHORIZED;
            }

            for (int j = 0; j < value.length(); j++) {
                if (value.charAt(j) < 0x21 || value.charAt(j) > 0x7e) {
                    return Reason.ISSUER_NOT_AUTHORIZED;
                }
            }

            if (parameters.putIfAbsent(key, value) != null) {
                return Reason.UNSUPPORTED_PARAMETERS;
            }
        }

        for (var parameter : parameters.entrySet()) {
            if (!Set.of("accounturi", "validationmethods").contains(parameter.getKey())) {
                return Reason.UNSUPPORTED_PARAMETERS;
            }
            if (context == null) {
                return Reason.MISSING_BINDING_CONTEXT;
            }
            if (parameter.getKey().equals("accounturi")) {
                // RFC 8657 Section 3 requires the URI to identify the requesting account.
                // This implementation uses exact string comparison without normalization.
                if (context.accountUri().isEmpty()) {
                    return Reason.MISSING_BINDING_CONTEXT;
                }
                if (!context.accountUri().get().toString().equals(parameter.getValue())) {
                    return Reason.ACCOUNT_NOT_AUTHORIZED;
                }
            } else {
                if (context.validationMethod().isEmpty()) {
                    return Reason.MISSING_BINDING_CONTEXT;
                }
                // RFC 8657 Section 4: require the method used for this name.
                String methods = parameter.getValue();
                if (!matchesValidationMethod(methods, context.validationMethod().get())) {
                    return Reason.VALIDATION_METHOD_NOT_AUTHORIZED;
                }
            }
        }

        return Reason.ISSUER_AUTHORIZED;
    }

    /**
     * Parses attacker-controlled parameter tags without recursive regular expressions.
     */
    private static boolean validParameterTag(String tag) {
        if (tag.isEmpty() || !isAlphaNumeric(tag.charAt(0))
                || !isAlphaNumeric(tag.charAt(tag.length() - 1))) {
            return false;
        }

        for (int i = 1; i < tag.length() - 1; i++) {
            char c = tag.charAt(i);
            if (!isAlphaNumeric(c) && c != '-') {
                return false;
            }
        }

        return true;
    }

    /**
     * Validates every label, including labels after a matching method.
     */
    private static boolean matchesValidationMethod(String methods, String method) {
        boolean matched = false;
        for (String label : methods.split(",", -1)) {
            if (label.isEmpty()) {
                return false;
            }

            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if (!isAlphaNumeric(c) && c != '-') {
                    return false;
                }
            }

            matched |= label.equals(method);
        }

        return matched;
    }

    private static boolean isAlphaNumeric(char c) {
        return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9';
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            client.close();
        }
    }

    static DNSLookupException failure(DNSLookupException.Reason reason, String message) {
        return new DNSLookupException(new DNSLookupException.Failure(reason, message, List.of()));
    }

    /**
     * Tracks how much time and DNS work one CAA validation attempt may consume.
     * Bounds slow or excessive resolution so a request cannot keep following
     * parents, aliases or retries indefinitely.
     *
     * Lifetime and configuration:
     * - validate() creates one budget for the entire request. Every certificate
     *   name, parent lookup and alias follow-up uses that same budget.
     * - A new validation attempt gets a new budget. This mutable instance is
     *   used sequentially within its attempt, not shared between concurrent calls.
     * - Limits come from CAAPolicy.limits(), not administrator configuration.
     *   Current production limits are 5 seconds total, 1 second per query,
     *   128 queries and 16 alias transitions across the entire attempt.
     * - The validator's semaphore separately limits concurrent attempts.
     *
     * Accounting and enforcement:
     * - The deadline starts at construction and never resets. Production uses
     *   System.nanoTime() so wall-clock adjustments do not affect elapsed time;
     *   the alternate constructor accepts a controllable clock for tests.
     * - DNS adapters call reserveQuery() before each query, including retries,
     *   and reserveAlias() before each alias transition. Reservations consume
     *   allowance even if the subsequent operation fails.
     * - The validator calls check() between discovery steps, before accepting
     *   a name's result and after constructing the completed decision. Reusing
     *   an observation costs no query allowance, but does not bypass the shared
     *   deadline or interruption check.
     * - Adapters must cap each query timeout at the smaller of queryTimeout()
     *   and remaining(). For example, 300 ms left permits at most a 300 ms query,
     *   even though the per-query cap is 1 second.
     * - Exhausted allowances, elapsed time and interruption produce typed
     *   failures that prevent approval. The budget does not itself interrupt
     *   blocked I/O; adapters must enforce transport timeouts and cancellation.
     *
     * These are execution limits, not DNS TTLs or the completed decision's
     * eight-hour freshness limit. Another name does not restart the clock or
     * replenish the allowances.
     */
    static final class Budget implements CAADNSClient.LookupBudget {
        private final long started;
        private final LongSupplier clock;
        private final CAAPolicy.Limits limits;
        private int queries;
        private int aliases;

        Budget(CAAPolicy.Limits limits) {
            this(limits, System::nanoTime);
        }

        /**
         * Injects a monotonic clock for deadline tests without sleeping.
         */
        Budget(CAAPolicy.Limits limits, LongSupplier clock) {
            this.limits = limits;
            this.clock = clock;
            started = clock.getAsLong();
        }

        @Override
        public Duration remaining() {
            return remaining(clock.getAsLong());
        }

        private Duration remaining(long now) {
            long elapsed = now - started;
            return elapsed < 0 || elapsed >= limits.totalTimeout().toNanos() ? Duration.ZERO
                    : Duration.ofNanos(limits.totalTimeout().toNanos() - elapsed);
        }

        @Override
        public Duration queryTimeout() {
            return limits.queryTimeout();
        }

        @Override
        public void reserveQuery() throws DNSLookupException {
            check();
            if (++queries > limits.maxQueries()) {
                throw failure(DNSLookupException.Reason.LIMIT_EXCEEDED,
                        "CAA query limit exceeded");
            }
        }

        @Override
        public void reserveAlias() throws DNSLookupException {
            check();
            if (++aliases > limits.maxAliases()) {
                throw failure(DNSLookupException.Reason.LIMIT_EXCEEDED,
                        "CAA alias limit exceeded");
            }
        }

        /**
         * Checks cancellation and returns the sampled tick without consuming an allowance.
         * reserveQuery() and reserveAlias() additionally charge their counters
         * before the DNS client performs the corresponding work.
         */
        long check() throws DNSLookupException {
            long now = clock.getAsLong();
            if (Thread.currentThread().isInterrupted()) {
                throw failure(DNSLookupException.Reason.CANCELLED, "CAA check interrupted");
            }
            if (remaining(now).isZero()) {
                throw failure(DNSLookupException.Reason.TIMEOUT, "CAA deadline exceeded");
            }
            return now;
        }
    }
}
