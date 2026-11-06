// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/** Owns the configured validator and permits issuer submission only after CAA approval. */
public final class CAAIssuanceGate implements AutoCloseable {
    private final DefaultCAAValidator validator;
    private final AtomicBoolean closed = new AtomicBoolean();

    private CAAIssuanceGate(DefaultCAAValidator validator) { this.validator = validator; }

    /** Disabled by default, including when upgrading an instance without caa.conf. */
    public static CAAIssuanceGate open(Properties properties, ClassLoader loader) throws DNSLookupException {
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
        if (enabled.equals("false")) return new CAAIssuanceGate(null);
        CAAPolicy policy;
        try {
            policy = new CAAPolicy(Arrays.stream(properties.getProperty("issuerIdentifiers", "").split(",", -1))
                    .map(String::strip).collect(Collectors.toSet()));
        } catch (IllegalArgumentException e) {
            throw DefaultCAAValidator.failure(DNSLookupException.Reason.CONFIGURATION, "Invalid CAA issuer identifiers");
        }
        var settings = new HashMap<String, String>();
        for (String key : properties.stringPropertyNames()) {
            if (key.startsWith("dns.settings.")) settings.put(key.substring(13), properties.getProperty(key));
        }
        CAADNSClient client = CAADNSClientLoader.open(properties.getProperty("dns.class", ""), loader,
                new CAADNSClientProvider.Config(settings));
        return new CAAIssuanceGate(new DefaultCAAValidator(client, policy));
    }

    public boolean isEnabled() { return validator != null; }

    /** Returns only after an unexpired approval, or when checking is explicitly disabled. */
    public void check(CAARequest request, Consumer<CAADecision> audit) throws CAAApprovalException {
        if (closed.get()) throw new IllegalStateException("CAA issuance gate is closed");
        if (validator != null) {
            CAADecision decision = validator.validate(request);
            audit.accept(decision);
            if (decision.outcome() != CAADecision.Outcome.ALLOW || !Instant.now().isBefore(decision.expiresAt())
                    || closed.get()) throw new CAAApprovalException(decision);
        }
    }

    /** Convenience for callers that submit through a callback after the check. */
    public <T> T issue(CAARequest request, Consumer<CAADecision> audit, Callable<T> submission) throws Exception {
        check(request, audit);
        return submission.call();
    }

    @Override public void close() {
        if (closed.compareAndSet(false, true) && validator != null) validator.close();
    }

    /** Typed refusal for the ACME host to persist and map to a problem document. */
    public static final class CAAApprovalException extends Exception {
        private static final long serialVersionUID = 1L;
        private final CAADecision decision;
        CAAApprovalException(CAADecision decision) {
            super("CAA authorization did not permit issuance");
            this.decision = decision;
        }
        public CAADecision decision() { return decision; }
    }
}
