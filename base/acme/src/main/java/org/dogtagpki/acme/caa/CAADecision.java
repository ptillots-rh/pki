// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Reports the aggregate CAA outcome, per-name results, and expiry. */
public record CAADecision(
        Outcome outcome,
        List<NameDecision> names,
        Instant checkedAt,
        Instant expiresAt) {
    public CAADecision {
        Objects.requireNonNull(outcome);
        names = List.copyOf(names);
        Objects.requireNonNull(checkedAt);
        Objects.requireNonNull(expiresAt);
        if (names.isEmpty()) {
            throw new IllegalArgumentException("Missing name decisions");
        }
        if (outcome != aggregateOutcome(names)) {
            throw new IllegalArgumentException("Contradictory aggregate outcome");
        }
        if (outcome == Outcome.ALLOW && !expiresAt.isAfter(checkedAt)) {
            throw new IllegalArgumentException("ALLOW decision must be usable at completion");
        }
    }

    /** An incomplete evaluation takes precedence over a denial; all names must allow. */
    private static Outcome aggregateOutcome(List<NameDecision> names) {
        Outcome aggregate = Outcome.ALLOW;
        for (NameDecision name : names) {
            if (name.outcome() == Outcome.ERROR) {
                return Outcome.ERROR;
            }
            if (name.outcome() == Outcome.DENY) {
                aggregate = Outcome.DENY;
            }
        }
        return aggregate;
    }

    /** Reports one certificate name's CAA outcome and discovery evidence. */
    public record NameDecision(
            CAARequest.CertificateName name,
            Outcome outcome,
            Reason reason,
            Optional<DNSDomainName> relevantOwner,
            List<CAADNSClient.LookupResult> discovery,
            Optional<DNSLookupException.Failure> failure) {
        public NameDecision {
            Objects.requireNonNull(name);
            Objects.requireNonNull(outcome);
            Objects.requireNonNull(reason);
            Objects.requireNonNull(relevantOwner);
            discovery = List.copyOf(discovery);
            Objects.requireNonNull(failure);
            boolean expectsDnsFailure = reason == Reason.DNS_FAILURE;
            if (expectsDnsFailure != failure.isPresent()) {
                throw new IllegalArgumentException("DNS_FAILURE reason requires matching failure details");
            }
            // Enumerate every reason so a future reason requires an explicit
            // authorization decision instead of inheriting a default outcome.
            Outcome expected = switch (reason) {
                case NO_RESTRICTION, ISSUER_AUTHORIZED -> Outcome.ALLOW;
                case DNS_FAILURE, EXPIRED -> Outcome.ERROR;
                case ISSUER_NOT_AUTHORIZED, UNKNOWN_CRITICAL_PROPERTY,
                        UNSUPPORTED_PARAMETERS, MISSING_BINDING_CONTEXT -> Outcome.DENY;
            };
            if (outcome != expected) {
                throw new IllegalArgumentException("Contradictory outcome and reason");
            }
            if (outcome == Outcome.ALLOW && discovery.isEmpty()) {
                throw new IllegalArgumentException("ALLOW requires DNS discovery evidence");
            }
        }
    }

    /** Distinguishes authorization, policy denial, and evaluation failure. */
    public enum Outcome { ALLOW, DENY, ERROR }

    /** Explains why CAA evaluation authorized, denied, or failed. */
    public enum Reason {
        NO_RESTRICTION, ISSUER_AUTHORIZED, ISSUER_NOT_AUTHORIZED,
        UNKNOWN_CRITICAL_PROPERTY, UNSUPPORTED_PARAMETERS,
        MISSING_BINDING_CONTEXT, DNS_FAILURE, EXPIRED
    }
}
