// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.util.List;
import java.util.Objects;

/** Transports a typed DNS lookup failure to the common CAA engine. */
public final class DNSLookupException extends Exception {
    private static final long serialVersionUID = 1L;
    private final Failure failure;

    public DNSLookupException(Failure failure) {
        super(failure.message());
        this.failure = failure;
    }

    public Failure failure() {
        return failure;
    }

    /** Carries a bounded failure message and immutable partial response evidence. */
    public record Failure(
            Reason reason, String message,
            List<CAADNSClient.ResponseEvidence> partialResponses) {
        public Failure {
            Objects.requireNonNull(reason);
            Objects.requireNonNull(message);
            partialResponses = List.copyOf(partialResponses);
            if (message.length() > 1024 || message.chars().anyMatch(Character::isISOControl)) {
                throw new IllegalArgumentException("Failure message must be bounded single-line text");
            }
        }
    }

    /** Identifies a stable DNS adapter or lookup failure category. */
    public enum Reason {
        CONFIGURATION, TIMEOUT, UNREACHABLE, RCODE_FAILURE,
        MALFORMED_RESPONSE, INCOMPLETE_ANSWER, ALIAS_LOOP,
        LIMIT_EXCEEDED, VALIDATION_FAILURE, CANCELLED
    }
}
