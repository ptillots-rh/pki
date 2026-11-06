// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Resolves CAA through aliases without performing parent discovery. */
public interface CAADNSClient extends AutoCloseable {
    /** Read-only validation behavior fixed by the selected provider. */
    ValidationMode validationMode();

    LookupResult resolveCaa(DNSDomainName candidate, LookupBudget budget)
            throws DNSLookupException;

    /**
     * Releases owned resources and cancels outstanding work. Must be idempotent
     * and safe alongside active calls; later lookups must fail as cancelled.
     * ACME stops admission and drains/cancels checks before closing its client.
     */
    void close();

    /** Returns terminal CAA data or absence with supporting DNS observations. */
    public record LookupResult(
            DNSDomainName candidate,
            DNSDomainName terminalName,
            LookupKind kind,
            List<CAARecord> records,
            List<AliasStep> aliases,
            List<ResponseEvidence> responses,
            Optional<NegativeEvidence> negativeEvidence) {
        private static final int RCODE_NOERROR = 0;
        private static final int RCODE_NXDOMAIN = 3;

        public LookupResult {
            Objects.requireNonNull(candidate);
            Objects.requireNonNull(terminalName);
            Objects.requireNonNull(kind);
            records = List.copyOf(records);
            aliases = List.copyOf(aliases);
            responses = List.copyOf(responses);
            Objects.requireNonNull(negativeEvidence);
            if (responses.isEmpty()) {
                throw new IllegalArgumentException("Missing DNS response evidence");
            }
            if (responses.stream().anyMatch(response -> response.rcode() != RCODE_NOERROR
                    && response.rcode() != RCODE_NXDOMAIN)) {
                throw new IllegalArgumentException("Failed DNS response cannot be a successful lookup");
            }
            int terminalRcode = responses.get(responses.size() - 1).rcode();
            int expectedTerminalRcode = kind == LookupKind.NXDOMAIN ? RCODE_NXDOMAIN : RCODE_NOERROR;
            if (terminalRcode != expectedTerminalRcode) {
                throw new IllegalArgumentException("Lookup kind contradicts response RCODE");
            }
            if (kind == LookupKind.RRSET) {
                if (responses.stream().anyMatch(response -> response.rcode() != RCODE_NOERROR)) {
                    throw new IllegalArgumentException("Positive lookup cannot contain an NXDOMAIN response");
                }
                if (records.isEmpty() || negativeEvidence.isPresent()) {
                    throw new IllegalArgumentException("Positive lookup requires records and no negative evidence");
                }
                if (records.stream().anyMatch(r -> !r.owner().equals(terminalName))) {
                    throw new IllegalArgumentException("CAA owner differs from terminal name");
                }
            } else {
                if (!records.isEmpty() || negativeEvidence.isEmpty()) {
                    throw new IllegalArgumentException("Negative lookup requires absence evidence and no CAA records");
                }
                NegativeEvidence negative = negativeEvidence.get();
                if (negative.kind() != kind || !negative.terminalName().equals(terminalName)) {
                    throw new IllegalArgumentException("Negative evidence must match lookup kind and terminal name");
                }
            }
            DNSDomainName next = candidate;
            Set<DNSDomainName> visited = new HashSet<>();
            visited.add(candidate);
            for (AliasStep alias : aliases) {
                if (!next.equals(alias.source()) || !visited.add(alias.target())) {
                    throw new IllegalArgumentException("Disconnected or looping alias chain");
                }
                next = alias.target();
            }
            if (!next.equals(terminalName)) {
                throw new IllegalArgumentException("Alias chain does not reach terminal name");
            }
        }
    }

    /** Distinguishes a positive RRset from terminal record or name absence. */
    public enum LookupKind { RRSET, NODATA, NXDOMAIN }

    /** Preserves a CAA resource record's owner, TTL, flags, tag, and value. */
    public record CAARecord(
            DNSDomainName owner, long ttlSeconds, int flags,
            String tag, byte[] value) {
        public CAARecord {
            Objects.requireNonNull(owner);
            Objects.requireNonNull(tag);
            value = value.clone();
            // TTL is a nonnegative 31-bit value. RDATA permits 65535 octets:
            // one flags octet, one tag-length octet, then the tag and value.
            if (ttlSeconds < 0 || ttlSeconds > 0x7fffffffL || flags < 0 || flags > 255
                    || !tag.matches("[A-Za-z0-9]{1,255}") || tag.length() + value.length > 65533) {
                throw new IllegalArgumentException("Invalid CAA record fields");
            }
        }

        @Override
        public byte[] value() {
            return value.clone();
        }
    }

    /** Records one connected alias transition used during resolution. */
    public record AliasStep(
            DNSDomainName source, DNSDomainName target,
            AliasKind kind, long ttlSeconds) {
        public AliasStep {
            Objects.requireNonNull(source);
            Objects.requireNonNull(target);
            Objects.requireNonNull(kind);
            if (source.equals(target) || ttlSeconds < 0 || ttlSeconds > 0x7fffffffL) {
                throw new IllegalArgumentException("Invalid alias step");
            }
        }
    }

    /** Identifies an alias mechanism when its provenance is known. */
    public enum AliasKind { CNAME, DNAME_SYNTHESIS }

    /** Records resolver, transport, timing, and validation observations. */
    public record ResponseEvidence(
            String resolverId,
            DNSDomainName question, int rcode, boolean authenticatedData,
            DNSSECStatus validationStatus, ValidationAssurance assurance,
            Instant receivedAt, String transport,
            Optional<ExtendedError> diagnostic) {
        public ResponseEvidence {
            Objects.requireNonNull(resolverId);
            Objects.requireNonNull(question);
            Objects.requireNonNull(validationStatus);
            Objects.requireNonNull(assurance);
            Objects.requireNonNull(receivedAt);
            Objects.requireNonNull(transport);
            Objects.requireNonNull(diagnostic);
            if (rcode < 0 || rcode > 4095 || resolverId.isBlank()) {
                throw new IllegalArgumentException("Invalid DNS response identity or RCODE");
            }
            boolean classificationMatchesAssurance = switch (assurance) {
                case NONE -> validationStatus == DNSSECStatus.UNCHECKED;
                case TRUSTED_RESOLVER -> validationStatus == DNSSECStatus.PROVEN_INSECURE
                        || validationStatus == DNSSECStatus.UNCLASSIFIED
                        || (validationStatus == DNSSECStatus.SECURE && authenticatedData);
                case LOCAL_VALIDATOR -> validationStatus == DNSSECStatus.SECURE
                        || validationStatus == DNSSECStatus.PROVEN_INSECURE;
            };
            if (!classificationMatchesAssurance) {
                throw new IllegalArgumentException("Contradictory validation status and assurance");
            }
        }
    }

    /** Describes terminal DNS absence and optional negative-cache metadata. */
    public record NegativeEvidence(
            DNSDomainName terminalName, LookupKind kind,
            Optional<SOAEvidence> soa) {
        public NegativeEvidence {
            Objects.requireNonNull(terminalName);
            Objects.requireNonNull(kind);
            Objects.requireNonNull(soa);
            if (kind == LookupKind.RRSET) {
                throw new IllegalArgumentException("Expected negative lookup kind");
            }
        }
    }

    /** Retains SOA fields needed to determine negative-cache lifetime. */
    public record SOAEvidence(
            DNSDomainName owner, long ttlSeconds, long minimumSeconds) {
        public SOAEvidence {
            Objects.requireNonNull(owner);
            if (ttlSeconds < 0 || ttlSeconds > 0x7fffffffL || minimumSeconds < 0 || minimumSeconds > 0xffffffffL) {
                throw new IllegalArgumentException("Invalid SOA TTL or MINIMUM");
            }
        }
    }

    /** Carries an optional DNS extended-error code and diagnostic text. */
    public record ExtendedError(int code, Optional<String> text) {
        public ExtendedError {
            Objects.requireNonNull(text);
            if (code < 0 || code > 65535 || text.map(String::length).orElse(0) > 1024) {
                throw new IllegalArgumentException("Invalid or oversized extended error");
            }
        }
    }

    /** Describes fixed provider behavior; this is not a configuration parameter. */
    public enum ValidationMode {
        UNCHECKED, DELEGATED_ENFORCING, LOCAL_ENFORCING
    }

    /** Classifies the DNSSEC status established for an observed response. */
    public enum DNSSECStatus {
        SECURE, PROVEN_INSECURE, UNCLASSIFIED, UNCHECKED
    }

    /** Identifies the trusted source of a validation classification. */
    public enum ValidationAssurance { NONE, TRUSTED_RESOLVER, LOCAL_VALIDATOR }

    /** Shares one deadline and query/alias allowance across a CAA attempt. */
    public interface LookupBudget {
        /** Returns time left on the monotonic attempt deadline, clamped at zero. */
        Duration remaining();
        /** Returns the per-query cap; a client must also respect remaining(). */
        Duration queryTimeout();
        void reserveQuery() throws DNSLookupException;
        void reserveAlias() throws DNSLookupException;
    }
}
