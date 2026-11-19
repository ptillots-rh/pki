// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.server;

import java.io.BufferedReader;
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
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEError;
import org.dogtagpki.acme.ACMEException;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.caa.CAADecision;
import org.dogtagpki.acme.caa.CAADNSClient.LookupResult;
import org.dogtagpki.acme.caa.CAADNSClient.ResponseEvidence;
import org.dogtagpki.acme.caa.CAAIssuanceGate;
import org.dogtagpki.acme.caa.CAARequest;
import org.dogtagpki.acme.caa.DNSDomainName;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Connects ACME order finalization to the shared CAA issuance gate.
 * ACMEEngine creates one instance at startup and closes it at shutdown.
 *
 * Responsibilities:
 * - Load the instance's CAA configuration and own the resulting gate.
 * - Build trusted account and validation-method context for each CSR name.
 * - Record CAA decisions and translate rejections into persisted order errors.
 *
 * Finalization flow:
 *   validated CSR
 *        |
 *        v
 *   build trusted context -> on failure: persist invalid order
 *        |
 *        v
 *   check CAA gate        -> on rejection: persist invalid order
 *        |
 *        v
 *   return to servlet -> submit CSR to issuer
 *
 * Boundaries:
 * - The servlet validates the CSR signature and order names before calling here.
 * - The shared validator performs DNS discovery and CAA policy evaluation.
 * - The account URI comes from configured server identity. Method facts come
 *   from stored authorizations owned by the account, separately for each name.
 * - The servlet submits to the issuer only after this check returns normally.
 *
 * The CA profile must preserve the checked identities. Signing must also remain
 * within the accepted decision lifetime; this adapter controls submission and
 * does not enforce a remote CA's processing delay.
 */
final class ACMECAAValidator implements AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(ACMECAAValidator.class);

    private final ACMEEngine engine;
    private final CAAIssuanceGate gate;

    /**
     * Loads administrator configuration and opens the gate for this ACME engine.
     * The webapp's class loader locates the configured optional DNS provider.
     *
     * Configuration handling:
     * - A missing file uses empty properties, preserving default-off behavior
     *   for installations created before CAA configuration was introduced.
     * - Other read errors and invalid configuration fail initialization.
     * - Enabled CAA requires baseURL in engine.conf so account binding can use
     *   configured server identity instead of a request-supplied origin.
     * - Validate its URI syntax and account-origin rules during startup,
     *   before an unusable origin can cause enrollment failures.
     *
     * The gate owns any opened DNS client. If the baseURL requirement fails
     * after opening the gate, close it before propagating the exception.
     * Configuration is loaded once; changes require an ACME instance restart.
     */
    ACMECAAValidator(ACMEEngine engine, String filename) throws Exception {
        this.engine = engine;
        Properties properties = new Properties();

        try (BufferedReader reader = Files.newBufferedReader(Path.of(filename))) {
            properties.load(reader);
        } catch (NoSuchFileException e) {
            // Older installations have no CAA policy. Other I/O errors fail startup.
        }

        gate = CAAIssuanceGate.open(properties, getClass().getClassLoader());
        try {
            if (gate.isEnabled()) {
                if (engine.getBaseURL() == null) {
                    throw new IllegalArgumentException(
                            "CAA requires baseURL in engine.conf for trusted account binding");
                }

                // Reject unusable account origins during startup, using the
                // same rules as registration and issuance-time account binding.
                ACMEEngine.validateAccountOrigin(engine.getBaseURL().toURI());
            }
        } catch (Exception e) {
            gate.close();
            throw e;
        }

        logger.info("ACME CAA checking enabled: {}", gate.isEnabled());
        if (gate.isEnabled()) {
            // Log only known operational settings. Other provider properties may
            // contain credentials and must not be dumped into the server log.
            logger.info("ACME CAA configuration provider={} issuers={} resolver={} port={}",
                    logValue(properties.getProperty("dns.class")),
                    logValue(properties.getProperty("issuerIdentifiers")),
                    logValue(properties.getProperty("dns.settings.server")),
                    logValue(properties.getProperty("dns.settings.port")));
        }
    }

    /**
     * Closes the gate and its owned validator resources.
     *
     * - Repeated calls are safe because gate shutdown is idempotent.
     * - ACMEEngine retains this instance after closing it. Late finalization
     *   requests encounter the closed gate and cannot proceed through it.
     */
    @Override
    public void close() {
        gate.close();
    }

    /**
     * Checks CAA immediately before the servlet submits the validated CSR.
     * The caller has already checked the CSR signature and its order names.
     *
     * Enabled policy:
     * - Build a request from CSR names and current account-owned authorizations.
     * - Pass it to the gate, recording the evaluation through logDecision().
     * - Record submission permission only after the gate returns successfully.
     *   An observed ALLOW can still be rejected for expiry or shutdown.
     *
     * Rejected requests are mapped to ACME problems:
     * - unauthorized: trusted issuance context could not be established.
     * - caa: the gate rejected a policy DENY decision.
     * - dns: another gate rejection prevented usable CAA approval.
     *
     * rejectCAA() persists the invalid order before the problem is thrown.
     * Lifecycle and persistence errors propagate to the caller as failures.
     *
     * Disabled policy skips context construction and DNS evaluation. Normal
     * return then preserves ordinary enrollment behavior without a CAA approval.
     */
    void validate(ACMEAccount account, ACMEOrder order, PKCS10 pkcs10) throws Exception {
        CAARequest request = null;
        if (gate.isEnabled()) {
            try {
                request = createRequest(engine, account, order, pkcs10);
            } catch (Exception e) {
                String reason = e instanceof MissingAuthorizationException
                        ? "MISSING_AUTHORIZATION" : "INVALID_CONTEXT";
                logger.warn("ACME CAA order={} submission=blocked reason=CONTEXT contextFailure={} errorType={}",
                        order.getID(), reason, e.getClass().getSimpleName());
                throw rejectCAA(account, order, "unauthorized", "Cannot establish current CAA issuance context");
            }
        }

        try {
            CAARequest currentRequest = request;
            gate.check(request, decision -> logDecision(order.getID(), currentRequest, decision));
            if (gate.isEnabled()) {
                logger.info("ACME CAA order={} submission=permitted", order.getID());
            }
        } catch (CAAIssuanceGate.CAAApprovalException e) {
            logger.info("ACME CAA order={} submission=blocked reason={} evaluation={}",
                    order.getID(), e.reason(), e.decision().outcome());
            boolean denied = e.decision().outcome() == CAADecision.Outcome.DENY;
            throw rejectCAA(account, order, denied ? "caa" : "dns",
                    denied ? "CAA policy does not authorize issuance"
                            : "CAA lookup could not establish authorization");
        }
    }

    /**
     * Records each certificate name's evaluation and supporting DNS observations.
     * These messages describe evaluation; submission permission is logged later,
     * after the gate has also checked decision expiry and shutdown.
     *
     * Per-name fields:
     * - name and wildcard identify the requested certificate identity.
     * - method identifies the successful challenge method, or none if unavailable.
     * - evaluation and reason explain the policy or lookup outcome.
     * - dnsFailure gives the typed operational failure when one is available.
     * - owner identifies the selected CAA RRset, possibly at a parent or alias.
     * - checkedAt and expiresAt describe the overall attempt's decision lifetime.
     *
     * Log discovery responses and any partial responses retained on failure so
     * operators can trace the result even when a lookup did not complete.
     * Raw CAA values, account URIs and resolver diagnostic text are omitted.
     */
    private static void logDecision(String orderID, CAARequest request, CAADecision decision) {
        for (CAADecision.NameDecision name : decision.names()) {
            CAARequest.IssuanceContext context = request.contexts().get(name.name());
            String method = context == null ? "none" : context.validationMethod().orElse("none");
            logger.info("ACME CAA order={} name={} wildcard={} method={} evaluation={} reason={} "
                            + "dnsFailure={} owner={} checkedAt={} expiresAt={}",
                    orderID, name.name().baseName().asciiAbsoluteName(), name.name().wildcard(),
                    method, name.outcome(), name.reason(), name.failure().map(f -> f.reason().name()).orElse("none"),
                    name.relevantOwner().map(DNSDomainName::asciiAbsoluteName).orElse("none"),
                    decision.checkedAt(), decision.expiresAt());

            for (LookupResult lookup : name.discovery()) {
                for (ResponseEvidence response : lookup.responses()) {
                    logResponse(orderID, response);
                }
            }

            name.failure().ifPresent(failure -> {
                for (ResponseEvidence response : failure.partialResponses()) {
                    logResponse(orderID, response);
                }
            });
        }
    }

    /**
     * Records one DNS response's resolver, question, transport and received time.
     * The response code and optional Extended DNS Error code help explain failures.
     *
     * The dnssec field carries the adapter's validation status:
     * - SECURE: the trusted enforcing resolver reported authenticated data.
     * - UNCLASSIFIED: the trusted resolver accepted the response without AD.
     *   This status alone does not establish that the domain is unsigned.
     * - UNTRUSTED: the observation cannot supply accepted discovery evidence.
     *
     * Codes retain their numeric values and include RFC labels for common errors.
     * Extended error diagnostic text is omitted because it is resolver-supplied.
     */
    private static void logResponse(String orderID, ResponseEvidence response) {
        logger.info("ACME CAA order={} question={} resolver={} transport={} rcode={} rcodeName={} "
                        + "dnssec={} receivedAt={} ede={} edeName={}",
                orderID, response.question().asciiAbsoluteName(), response.resolverId(), response.transport(),
                response.rcode(), responseCodeName(response.rcode()), response.validationStatus(), response.receivedAt(),
                response.diagnostic().map(diagnostic -> Integer.toString(diagnostic.code())).orElse("none"),
                response.diagnostic().map(diagnostic -> extendedErrorName(diagnostic.code())).orElse("none"));
    }

    /**
     * Keeps configuration fields on one bounded log line. Missing optional
     * settings are resolved by the provider rather than by this adapter.
     */
    private static String logValue(String value) {
        if (value == null) {
            return "provider-default";
        }

        StringBuilder result = new StringBuilder();
        int limit = Math.min(value.length(), 1024);
        for (int i = 0; i < limit; i++) {
            char character = value.charAt(i);
            result.append(Character.isISOControl(character) ? ' ' : character);
        }
        if (value.length() > limit) {
            result.append("...");
        }
        return result.toString();
    }

    /**
     * Names standard response codes from RFC 1035 Section 4.1.1.
     * Unknown codes remain identifiable by the numeric rcode field.
     */
    private static String responseCodeName(int code) {
        return switch (code) {
            case 0 -> "NOERROR";
            case 1 -> "FORMERR";
            case 2 -> "SERVFAIL";
            case 3 -> "NXDOMAIN";
            case 4 -> "NOTIMP";
            case 5 -> "REFUSED";
            default -> "UNKNOWN";
        };
    }

    /**
     * Names DNSSEC-related extended errors from RFC 8914 Sections 4.6-4.13.
     * Labels explain observations and do not change validation or trust policy.
     */
    private static String extendedErrorName(int code) {
        return switch (code) {
            case 5 -> "DNSSEC_INDETERMINATE";
            case 6 -> "DNSSEC_BOGUS";
            case 7 -> "SIGNATURE_EXPIRED";
            case 8 -> "SIGNATURE_NOT_YET_VALID";
            case 9 -> "DNSKEY_MISSING";
            case 10 -> "RRSIGS_MISSING";
            case 11 -> "NO_ZONE_KEY_BIT_SET";
            case 12 -> "NSEC_MISSING";
            default -> "UNKNOWN";
        };
    }

    /**
     * Marks missing current ownership separately from other context failures.
     * The log uses this category without exposing authorization or account data.
     */
    private static final class MissingAuthorizationException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        MissingAuthorizationException() {
            super("Missing current account-owned authorization for CAA name");
        }
    }

    /**
     * Builds an ACME problem and persists the order's terminal failure state.
     * type supplies the ACME problem suffix; detail supplies its client message.
     *
     * Order changes:
     * - Set status to invalid and attach the serialized problem document.
     * - Apply the configured invalid-order expiration policy.
     * - Persist the updated order through the engine before returning.
     *
     * The caller throws the returned HTTP 403 exception. If persistence fails,
     * propagate that failure instead; the request still cannot reach the issuer.
     */
    private ACMEException rejectCAA(ACMEAccount account, ACMEOrder order, String type, String detail)
            throws Exception {
        ACMEError error = new ACMEError();
        error.setType("urn:ietf:params:acme:error:" + type);
        error.setDetail(detail);

        order.setStatus("invalid");
        order.setError(error.toJSON());
        order.setExpirationTime(engine.getPolicy().getInvalidOrderExpirationTime(new Date()));
        engine.updateOrder(account, order);

        return new ACMEException(HttpServletResponse.SC_FORBIDDEN, error);
    }

    /**
     * Extracts intended certificate DNS names from the validated CSR and builds
     * their CAA context through the name-set overload below.
     *
     * - CertUtil supplies the DNS SANs and any DNS name represented by the CN.
     * - Every extracted name must have current account-owned authorization.
     * - The caller remains responsible for the earlier CSR validation stage.
     *
     * These are the names intended for issuance. A configured CA profile must
     * preserve them; this method does not inspect a signed certificate.
     */
    static CAARequest createRequest(ACMEEngine engine, ACMEAccount account, ACMEOrder order, PKCS10 pkcs10)
            throws Exception {
        return createRequest(engine, account, order, CertUtil.getDNSNames(pkcs10));
    }

    /**
     * Maps intended certificate names to trusted ACME account and method facts.
     * The caller supplies names already extracted from intended issuance data.
     *
     * Authorization selection:
     * - Read only authorization IDs attached to this order.
     * - Require account ownership, valid status, a future expiration and a DNS
     *   identifier. Other authorizations supply no context.
     * - Normalize DNS names for matching and preserve wildcard identity.
     *   Authorization for example.com cannot stand in for *.example.com.
     *
     * Validation-method selection, separately for each authorized identity:
     * - Count only valid challenges with recorded, nonfuture validation times.
     * - Repeated evidence for the same method still identifies one method.
     * - No usable method or several distinct methods leaves the method absent.
     *   The policy engine cannot use that absence to satisfy a restricted grant.
     *
     * Request construction:
     * - Use the engine's configured account URI for account binding.
     * - Require authorization for every requested name; one missing identity
     *   prevents construction of the complete request.
     * - Attach context only to the requested names. A valid authorization can
     *   supply an empty method fact when its challenge history is unusable.
     */
    static CAARequest createRequest(ACMEEngine engine, ACMEAccount account, ACMEOrder order, Set<String> dnsNames)
            throws Exception {
        List<CAARequest.CertificateName> names = new ArrayList<>();
        Map<CAARequest.CertificateName, CAARequest.IssuanceContext> contexts = new HashMap<>();
        Optional<URI> accountUri = Optional.of(engine.getAccountURI(null, account.getID()));
        Map<CAARequest.CertificateName, Set<String>> authorizedMethods = new HashMap<>();
        Date now = new Date();

        // Ignore authorizations that cannot establish current ownership of a
        // DNS identity. Never borrow context from another account or name.
        for (String id : order.getAuthzIDs()) {
            ACMEAuthorization authz = engine.getDatabase().getAuthorization(id);
            if (authz == null || !account.getID().equals(authz.getAccountID()) || !"valid".equals(authz.getStatus())
                    || authz.getExpirationTime() == null || !authz.getExpirationTime().after(now)
                    || authz.getIdentifier() == null || !"dns".equals(authz.getIdentifier().getType())) {
                continue;
            }

            String identifier = authz.getIdentifier().getValue();
            CAARequest.CertificateName authorizedName = new CAARequest.CertificateName(
                    new DNSDomainName(identifier.endsWith(".") ? identifier : identifier + "."),
                    Boolean.TRUE.equals(authz.getWildcard()));
            Set<String> methods = authorizedMethods.computeIfAbsent(authorizedName, key -> new HashSet<>());

            // An authorization can be valid while older stored challenge
            // history is absent. Such history cannot establish method binding.
            if (authz.getChallenges() != null) {
                for (ACMEChallenge challenge : authz.getChallenges()) {
                    if ("valid".equals(challenge.getStatus()) && challenge.getValidationTime() != null
                            && !challenge.getValidationTime().after(now)) {
                        methods.add(challenge.getType());
                    }
                }
            }
        }

        // Construct context only for names in this CSR. Several authorizations
        // for the same method are harmless; different successful methods are
        // ambiguous, so do not choose whichever happens to be encountered first.
        for (String value : dnsNames) {
            boolean wildcard = value.startsWith("*.");
            String base = wildcard ? value.substring(2) : value;
            CAARequest.CertificateName name = new CAARequest.CertificateName(
                    new DNSDomainName(base.endsWith(".") ? base : base + "."), wildcard);
            names.add(name);

            Set<String> methods = authorizedMethods.get(name);
            if (methods == null) {
                throw new MissingAuthorizationException();
            }

            Optional<String> method = methods.size() == 1 ? Optional.of(methods.iterator().next()) : Optional.empty();
            contexts.put(name, new CAARequest.IssuanceContext(accountUri, method));
        }

        return new CAARequest(names, contexts);
    }
}
