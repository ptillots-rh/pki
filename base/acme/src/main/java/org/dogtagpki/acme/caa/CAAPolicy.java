// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.time.Duration;
import java.util.Objects;
import java.util.Set;

/** Defines administrator-controlled issuer identifiers with fixed initial limits. */
public record CAAPolicy(Set<String> issuerIdentifiers) {
    private static final Duration MAX_TIMEOUT = Duration.ofNanos(Long.MAX_VALUE);
    private static final Duration MAX_CHECK_TO_SIGN_AGE = Duration.ofHours(8);
    private static final Limits DEFAULT_LIMITS =
            new Limits(Duration.ofSeconds(5), Duration.ofSeconds(1), 128, 16, 8);

    public CAAPolicy {
        issuerIdentifiers = Set.copyOf(issuerIdentifiers);
        if (issuerIdentifiers.isEmpty()) {
            throw new IllegalArgumentException("Missing issuer identifiers");
        }
        for (String issuer : issuerIdentifiers) {
            validateIssuerIdentifier(issuer);
        }
    }

    /** Validates configured issuer syntax without treating the issuer as a certificate name. */
    static void validateIssuerIdentifier(String issuer) {
        // Configuration uses a domain without the terminating root dot. Parse
        // the absolute form for syntax checking; retain the configured spelling.
        String absoluteName = new DNSDomainName(issuer + ".").asciiAbsoluteName();
        if (absoluteName.equals(".") || absoluteName.contains("_")) {
            throw new IllegalArgumentException("Expected issuer DNS identifier");
        }
    }

    /** Initial conservative issuance-age cap, not an administrator setting. */
    public Duration maxCheckToSignAge() {
        return MAX_CHECK_TO_SIGN_AGE;
    }

    /** Internal defaults; tests may construct other budgets without exposing configuration knobs. */
    public Limits limits() {
        return DEFAULT_LIMITS;
    }

    /** Bounds the time, query count, alias count, and concurrency of CAA checks. */
    public record Limits(
            Duration totalTimeout, Duration queryTimeout,
            int maxQueries, int maxAliases, int maxConcurrentChecks) {
        public Limits {
            validateTimeout(totalTimeout, "Total timeout");
            validateTimeout(queryTimeout, "Query timeout");
            if (maxQueries < 1 || maxAliases < 1 || maxConcurrentChecks < 1) {
                throw new IllegalArgumentException("CAA query, alias and concurrency limits must be positive");
            }
        }

        private static void validateTimeout(Duration timeout, String description) {
            Objects.requireNonNull(timeout, description);
            if (timeout.isZero() || timeout.isNegative()) {
                throw new IllegalArgumentException(description + " must be positive");
            }
            // Deadline accounting uses signed long nanoseconds. Check its range
            // explicitly rather than invoking toNanos() solely for its exception.
            if (timeout.compareTo(MAX_TIMEOUT) > 0) {
                throw new IllegalArgumentException(description + " exceeds the nanosecond deadline range");
            }
        }
    }
}
