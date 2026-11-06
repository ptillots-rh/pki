// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;

import org.dogtagpki.acme.caa.CAADNSClient.LookupResult;
import org.dogtagpki.acme.caa.CAADecision.NameDecision;
import org.dogtagpki.acme.caa.CAADecision.Outcome;
import org.dogtagpki.acme.caa.CAADecision.Reason;

/** Shared CAA discovery and policy, independent of DNS toolkit and enrollment protocol. */
public final class DefaultCAAValidator implements CAAValidator, AutoCloseable {
    private final CAADNSClient client;
    private final CAAPolicy policy;
    private final Semaphore checks;
    private final AtomicBoolean closed = new AtomicBoolean();

    public DefaultCAAValidator(CAADNSClient client, CAAPolicy policy) {
        this.client = java.util.Objects.requireNonNull(client);
        this.policy = java.util.Objects.requireNonNull(policy);
        checks = new Semaphore(policy.limits().maxConcurrentChecks());
    }

    @Override
    public CAADecision validate(CAARequest request) {
        Instant started = Instant.now();
        Budget budget = new Budget(policy.limits());
        List<NameDecision> decisions = new ArrayList<>();
        Map<DNSDomainName, LookupResult> observations = new HashMap<>();
        boolean admitted = !closed.get() && checks.tryAcquire();
        try {
            for (CAARequest.CertificateName name : request.names()) {
                List<LookupResult> discovery = new ArrayList<>();
                try {
                    if (!admitted || closed.get()) {
                        throw failure(closed.get() ? DNSLookupException.Reason.CANCELLED
                                : DNSLookupException.Reason.LIMIT_EXCEEDED, "CAA checker unavailable");
                    }
                    DNSDomainName candidate = name.baseName();
                    Reason reason = Reason.NO_RESTRICTION;
                    Optional<DNSDomainName> owner = Optional.empty();
                    while (!candidate.asciiAbsoluteName().equals(".")) {
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
                        // RFC 8659: climb the original candidate, never an alias target.
                        String original = candidate.asciiAbsoluteName();
                        String parent = original.substring(original.indexOf('.') + 1);
                        candidate = new DNSDomainName(parent.isEmpty() ? "." : parent);
                    }
                    budget.check();
                    Outcome outcome = reason == Reason.NO_RESTRICTION || reason == Reason.ISSUER_AUTHORIZED
                            ? Outcome.ALLOW : Outcome.DENY;
                    decisions.add(new NameDecision(name, outcome, reason, owner, discovery, Optional.empty()));
                } catch (DNSLookupException e) {
                    decisions.add(new NameDecision(name, Outcome.ERROR, Reason.DNS_FAILURE,
                            Optional.empty(), discovery, Optional.of(e.failure())));
                }
            }
        } finally {
            if (admitted) checks.release();
        }
        Instant finished = Instant.now();
        Outcome outcome = decisions.stream().anyMatch(d -> d.outcome() == Outcome.ERROR) ? Outcome.ERROR
                : decisions.stream().anyMatch(d -> d.outcome() == Outcome.DENY) ? Outcome.DENY : Outcome.ALLOW;
        // No cross-request cache or reusable authorization token. Cap age from
        // the oldest response, including parent/alias observations, at eight hours.
        Instant oldest = observations.values().stream().flatMap(r -> r.responses().stream())
                .map(CAADNSClient.ResponseEvidence::receivedAt).min(Instant::compareTo).orElse(started);
        Instant expires = oldest.plus(policy.maxCheckToSignAge());
        if (closed.get()) {
            var cancelled = failure(DNSLookupException.Reason.CANCELLED, "CAA checker closed").failure();
            decisions = decisions.stream().map(d -> new NameDecision(d.name(), Outcome.ERROR, Reason.DNS_FAILURE,
                    d.relevantOwner(), d.discovery(), Optional.of(cancelled))).toList();
            outcome = Outcome.ERROR;
        } else if (!expires.isAfter(finished)) {
            decisions = request.names().stream().map(name -> new NameDecision(name, Outcome.ERROR, Reason.EXPIRED,
                    Optional.empty(), List.of(), Optional.<DNSLookupException.Failure>empty())).toList();
            outcome = Outcome.ERROR;
        }
        return new CAADecision(outcome, decisions, finished, expires);
    }

    /** Rejects a provider that returns assurance contradicting its fixed contract. */
    private void verifyAssurance(DNSDomainName candidate, LookupResult result) throws DNSLookupException {
        if (!candidate.equals(result.candidate())) {
            throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE, "CAA candidate mismatch");
        }
        for (var response : result.responses()) {
            boolean valid = switch (client.validationMode()) {
                case UNCHECKED -> response.assurance() == CAADNSClient.ValidationAssurance.NONE;
                case DELEGATED_ENFORCING -> response.assurance() == CAADNSClient.ValidationAssurance.TRUSTED_RESOLVER;
                case LOCAL_ENFORCING -> response.assurance() == CAADNSClient.ValidationAssurance.LOCAL_VALIDATOR;
            };
            if (!valid) throw failure(DNSLookupException.Reason.VALIDATION_FAILURE, "Missing required DNS assurance");
        }
    }

    private Reason evaluate(List<CAADNSClient.CAARecord> records, CAARequest.CertificateName name,
            CAARequest.IssuanceContext context) {
        Set<String> known = Set.of("issue", "issuewild", "iodef");
        for (var record : records) {
            if ((record.flags() & 128) != 0 && !known.contains(record.tag().toLowerCase(Locale.ROOT))) {
                return Reason.UNKNOWN_CRITICAL_PROPERTY;
            }
        }
        boolean wildcardPolicy = name.wildcard() && records.stream().anyMatch(r -> r.tag().equalsIgnoreCase("issuewild"));
        String tag = wildcardPolicy ? "issuewild" : "issue";
        List<CAADNSClient.CAARecord> applicable = records.stream().filter(r -> r.tag().equalsIgnoreCase(tag)).toList();
        if (applicable.isEmpty()) return Reason.NO_RESTRICTION;
        Reason denied = Reason.ISSUER_NOT_AUTHORIZED;
        for (var record : applicable) {
            Reason result = grant(record.value(), context);
            if (result == Reason.ISSUER_AUTHORIZED) return result;
            if (result != Reason.ISSUER_NOT_AUTHORIZED) denied = result;
        }
        return denied;
    }

    /** A malformed or unsatisfied property grants nothing; another property may grant. */
    private Reason grant(byte[] bytes, CAARequest.IssuanceContext context) {
        for (byte b : bytes) {
            int value = Byte.toUnsignedInt(b);
            if (value > 126 || (value < 32 && value != 9)) return Reason.ISSUER_NOT_AUTHORIZED;
        }
        String[] parts = new String(bytes, StandardCharsets.US_ASCII).split(";", -1);
        String issuer = parts[0].strip();
        try { CAAPolicy.validateIssuerIdentifier(issuer); } catch (IllegalArgumentException e) {
            return Reason.ISSUER_NOT_AUTHORIZED;
        }
        if (policy.issuerIdentifiers().stream().noneMatch(issuer::equalsIgnoreCase)) return Reason.ISSUER_NOT_AUTHORIZED;
        Map<String, String> parameters = new HashMap<>();
        for (int i = 1; i < parts.length; i++) {
            String part = parts[i].strip();
            if (part.isEmpty() && parts.length == 2) continue;
            if (!part.matches("[A-Za-z0-9]+(?:-+[A-Za-z0-9]+)*[ \\t]*=[ \\t]*[\\x21-\\x3A\\x3C-\\x7E]*")) {
                return Reason.ISSUER_NOT_AUTHORIZED;
            }
            String[] parameter = part.split("=", 2);
            String key = parameter[0].strip();
            if (parameters.putIfAbsent(key, parameter[1].strip()) != null) return Reason.UNSUPPORTED_PARAMETERS;
        }
        for (var parameter : parameters.entrySet()) {
            if (!Set.of("accounturi", "validationmethods").contains(parameter.getKey())) return Reason.UNSUPPORTED_PARAMETERS;
            if (context == null) return Reason.MISSING_BINDING_CONTEXT;
            if (parameter.getKey().equals("accounturi")) {
                // RFC 8657: compare the account URI as a string without normalization.
                if (context.accountUri().isEmpty()) return Reason.MISSING_BINDING_CONTEXT;
                if (!context.accountUri().get().toString().equals(parameter.getValue())) return Reason.ISSUER_NOT_AUTHORIZED;
            } else {
                if (context.validationMethod().isEmpty()) return Reason.MISSING_BINDING_CONTEXT;
                String methods = parameter.getValue();
                if (!methods.matches("[A-Za-z0-9-]+(?:,[A-Za-z0-9-]+)*")
                        || !List.of(methods.split(",")).contains(context.validationMethod().get())) {
                    return Reason.ISSUER_NOT_AUTHORIZED;
                }
            }
        }
        return Reason.ISSUER_AUTHORIZED;
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) client.close();
    }

    static DNSLookupException failure(DNSLookupException.Reason reason, String message) {
        return new DNSLookupException(new DNSLookupException.Failure(reason, message, List.of()));
    }

    /** One monotonic deadline and allowance shared by all names in an attempt. */
    static final class Budget implements CAADNSClient.LookupBudget {
        private final long started = System.nanoTime();
        private final CAAPolicy.Limits limits;
        private int queries;
        private int aliases;

        Budget(CAAPolicy.Limits limits) { this.limits = limits; }
        @Override public Duration remaining() {
            long elapsed = System.nanoTime() - started;
            return elapsed >= limits.totalTimeout().toNanos() ? Duration.ZERO
                    : Duration.ofNanos(limits.totalTimeout().toNanos() - elapsed);
        }
        @Override public Duration queryTimeout() { return limits.queryTimeout(); }
        @Override public void reserveQuery() throws DNSLookupException {
            check();
            if (++queries > limits.maxQueries()) throw failure(DNSLookupException.Reason.LIMIT_EXCEEDED, "CAA query limit exceeded");
        }
        @Override public void reserveAlias() throws DNSLookupException {
            check();
            if (++aliases > limits.maxAliases()) throw failure(DNSLookupException.Reason.LIMIT_EXCEEDED, "CAA alias limit exceeded");
        }
        void check() throws DNSLookupException {
            if (Thread.currentThread().isInterrupted()) throw failure(DNSLookupException.Reason.CANCELLED, "CAA check interrupted");
            if (remaining().isZero()) throw failure(DNSLookupException.Reason.TIMEOUT, "CAA deadline exceeded");
        }
    }
}
