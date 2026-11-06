// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.server;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;

import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEError;
import org.dogtagpki.acme.ACMEException;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.caa.CAADecision;
import org.dogtagpki.acme.caa.CAAIssuanceGate;
import org.dogtagpki.acme.caa.CAARequest;
import org.dogtagpki.acme.caa.DNSDomainName;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Adapts the CAA gate to ACME configuration, authorization context and order errors. */
final class ACMECAAValidator implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(ACMECAAValidator.class);
    private final ACMEEngine engine;
    private final CAAIssuanceGate gate;

    ACMECAAValidator(ACMEEngine engine, String filename) throws Exception {
        this.engine = engine;
        Properties properties = new Properties();
        try (var reader = Files.newBufferedReader(Path.of(filename))) {
            properties.load(reader);
        } catch (NoSuchFileException e) {
            // Older installations have no CAA policy. Other I/O errors must fail startup.
        }
        gate = CAAIssuanceGate.open(properties, getClass().getClassLoader());
        logger.info("ACME CAA checking enabled: {}", gate.isEnabled());
    }

    @Override public void close() { gate.close(); }

    /** Checks CAA for a validated CSR; the servlet remains responsible for issuing it. */
    void validate(ACMEAccount account, ACMEOrder order, PKCS10 pkcs10) throws Exception {
        CAARequest request = null;
        if (gate.isEnabled()) {
            try {
                request = createRequest(engine, account, order, pkcs10);
            } catch (Exception e) {
                logger.warn("Unable to establish trusted CAA request context for order {}", order.getID());
                throw rejectCAA(account, order, "unauthorized", "Cannot establish current CAA issuance context");
            }
        }
        try {
            gate.check(request, decision -> {
                // Do not log raw DNS values, account URIs or native diagnostics.
                for (var name : decision.names()) {
                    logger.info("ACME CAA order={} name={} wildcard={} outcome={} reason={}", order.getID(),
                            name.name().baseName().asciiAbsoluteName(), name.name().wildcard(),
                            name.outcome(), name.reason());
                }
            });
        } catch (CAAIssuanceGate.CAAApprovalException e) {
            boolean denied = e.decision().outcome() == CAADecision.Outcome.DENY;
            throw rejectCAA(account, order, denied ? "caa" : "dns",
                    denied ? "CAA policy does not authorize issuance" : "CAA lookup could not establish authorization");
        }
    }

    private ACMEException rejectCAA(ACMEAccount account, ACMEOrder order, String type, String detail) throws Exception {
        ACMEError error = new ACMEError();
        error.setType("urn:ietf:params:acme:error:" + type);
        error.setDetail(detail);
        order.setStatus("invalid");
        order.setError(error.toJSON());
        order.setExpirationTime(engine.getPolicy().getInvalidOrderExpirationTime(new Date()));
        engine.updateOrder(account, order);
        return new ACMEException(HttpServletResponse.SC_FORBIDDEN, error);
    }

    /** Uses CSR names and stored, account-owned authorizations, never caller-supplied binding facts. */
    static CAARequest createRequest(ACMEEngine engine, ACMEAccount account, ACMEOrder order, PKCS10 pkcs10) throws Exception {
        return createRequest(engine, account, order, CertUtil.getDNSNames(pkcs10));
    }

    /** Maps already-extracted certificate names to account-owned authorization facts. */
    static CAARequest createRequest(ACMEEngine engine, ACMEAccount account, ACMEOrder order, Set<String> dnsNames) throws Exception {
        List<CAARequest.CertificateName> names = new ArrayList<>();
        Map<CAARequest.CertificateName, CAARequest.IssuanceContext> contexts = new HashMap<>();
        Optional<URI> accountUri = Optional.empty();
        if (engine.getBaseURL() != null) {
            String base = engine.getBaseURL().toString().replaceAll("/+$", "");
            accountUri = Optional.of(URI.create(base + "/acct/" + account.getID()));
        }
        List<ACMEAuthorization> authorizations = new ArrayList<>();
        for (String id : order.getAuthzIDs()) authorizations.add(engine.getDatabase().getAuthorization(id));
        Date now = new Date();
        for (String value : dnsNames) {
            boolean wildcard = value.startsWith("*.");
            String base = wildcard ? value.substring(2) : value;
            var name = new CAARequest.CertificateName(new DNSDomainName(base.endsWith(".") ? base : base + "."), wildcard);
            names.add(name);
            Set<String> methods = new HashSet<>();
            boolean authorized = false;
            for (ACMEAuthorization authz : authorizations) {
                if (authz == null || !account.getID().equals(authz.getAccountID()) || !"valid".equals(authz.getStatus())
                        || authz.getExpirationTime() == null || !authz.getExpirationTime().after(now)
                        || !"dns".equals(authz.getIdentifier().getType())
                        || Boolean.TRUE.equals(authz.getWildcard()) != wildcard) continue;
                String identifier = authz.getIdentifier().getValue();
                var authorizedName = new DNSDomainName(identifier.endsWith(".") ? identifier : identifier + ".");
                if (!authorizedName.equals(name.baseName())) continue;
                authorized = true;
                if (authz.getChallenges() != null) authz.getChallenges().stream().filter(c -> "valid".equals(c.getStatus())
                        && c.getValidationTime() != null && !c.getValidationTime().after(now))
                        .map(c -> c.getType()).forEach(methods::add);
            }
            if (!authorized) throw new IllegalArgumentException("Missing current account-owned authorization for CAA name");
            // Ambiguous historical state must not select an arbitrary method.
            Optional<String> method = methods.size() == 1 ? Optional.of(methods.iterator().next()) : Optional.empty();
            contexts.put(name, new CAARequest.IssuanceContext(accountUri, method));
        }
        return new CAARequest(order.getID(), names, contexts);
    }

}
