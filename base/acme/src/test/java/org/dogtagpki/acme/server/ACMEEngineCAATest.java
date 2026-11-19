// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEException;
import org.dogtagpki.acme.ACMEIdentifier;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.caa.CAADNSClient;
import org.dogtagpki.acme.caa.CAADNSClientProvider;
import org.dogtagpki.acme.caa.CAARequest;
import org.dogtagpki.acme.caa.DNSDomainName;
import org.dogtagpki.acme.caa.DNSLookupException;
import org.dogtagpki.acme.database.InMemoryDatabase;
import org.dogtagpki.acme.issuer.ACMEIssuer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Tests the ACME host boundary around the shared CAA issuance gate.
 *
 * The real engine configuration and context mapping use stored account-owned
 * authorizations and CSR fixtures. A deterministic DNS provider and recording
 * issuer isolate finalization order, failure persistence and lifecycle behavior.
 * HTTP/JWS handling and CA signing are outside this suite; servlet tests cover
 * the HTTP handler, and the enrollment harness covers an installed CA backend.
 */
public class ACMEEngineCAATest {
    @TempDir Path directory;
    private static final List<String> EVENTS = new ArrayList<>();
    private static final DNSDomainName NAME = new DNSDomainName("www.example.com.");
    private Engine engine;
    private ACMEOrder order;
    private ACMEAccount issuanceAccount;
    private PKCS10 issuanceCSR;

    /**
     * Starts each case with one current account, authorization and CSR.
     */
    @BeforeEach
    void prepare() throws Exception {
        EVENTS.clear();
        Provider.value = "ca.example";
        Provider.fail = false;
        Provider.opens = 0;
        Provider.closes = 0;
        Provider.failureReason = DNSLookupException.Reason.RCODE_FAILURE;

        engine = new Engine();
        engine.setID("acme");
        order = new ACMEOrder();
        order.setID("order-1");
        order.setStatus("processing");

        Path engineConfig = directory.resolve("issuance-engine.conf");
        Files.writeString(engineConfig, "baseURL=https://acme.example/acme\n");
        engine.loadEngineConfig(engineConfig.toString());

        issuanceAccount = new ACMEAccount();
        issuanceAccount.setID("account-1");
        issuanceCSR = readCSR("caa-issuance.csr");
        order.setAccountID(issuanceAccount.getID());
        order.setAuthzIDs(new String[] {"authz-1"});

        engine.setDatabase(new InMemoryDatabase());
        engine.getDatabase().addAuthorization(authorization());

        engine.setIssuer(
                new ACMEIssuer() {
                    @Override
                    public String issueCertificate(PKCS10 csr) {
                        EVENTS.add("issue");
                        return "certificate-1";
                    }
                });
    }

    /**
     * Records the CSR, DNS and issuer boundaries to pin the required finalization order.
     */
    @Test
    void allowRunsAfterCsrValidationBeforeIssuerSubmission() throws Exception {
        configure(true);

        try {
            assertEquals("certificate-1", finalizeIssuance());
            assertEquals(List.of("csr", "dns", "issue"), EVENTS);
        } finally {
            engine.shutdownCAA();
        }
    }

    /**
     * An applicable deny grant must persist a CAA problem and stop before the CA backend.
     */
    @Test
    void denialPersistsInvalidOrderAndNeverCallsIssuer() throws Exception {
        configure(true);
        Provider.value = ";";
        try {
            ACMEException error = assertThrows(ACMEException.class, () -> finalizeIssuance());
            assertEquals("urn:ietf:params:acme:error:caa", error.getError().getType());
            assertEquals("invalid", order.getStatus());
            assertTrue(order.getError().contains("acme:error:caa"));
            assertEquals(List.of("csr", "dns", "persist-invalid"), EVENTS);
        } finally {
            engine.shutdownCAA();
        }
    }

    /**
     * A resolver failure must persist a DNS problem rather than become CAA absence.
     */
    @Test
    void dnsFailurePersistsInvalidOrderAndNeverCallsIssuer() throws Exception {
        configure(true);
        Provider.fail = true;
        try {
            ACMEException error = assertThrows(ACMEException.class, () -> finalizeIssuance());
            assertEquals("urn:ietf:params:acme:error:dns", error.getError().getType());
            assertEquals(List.of("csr", "dns", "persist-invalid"), EVENTS);
        } finally {
            engine.shutdownCAA();
        }
    }

    /**
     * An older installation without caa.conf retains ordinary enrollment behavior.
     */
    @Test
    void missingConfigurationDisablesCaaWithoutLoadingAnyProvider() throws Exception {
        engine.initCAA(directory.resolve("does-not-exist.conf").toString());
        try {
            assertEquals("certificate-1", finalizeIssuance());
            assertEquals(List.of("csr", "issue"), EVENTS);
        } finally {
            engine.shutdownCAA();
        }
    }

    /**
     * CAA must not perform lookups for a CSR rejected by the earlier validation stage.
     */
    @Test
    void invalidCsrDoesNotReachDnsOrIssuer() throws Exception {
        configure(true);
        engine.invalidCSR = true;
        try {
            assertThrows(Exception.class, () -> finalizeIssuance());
            assertEquals(List.of("csr"), EVENTS);
        } finally {
            engine.shutdownCAA();
        }
    }

    /**
     * Retaining the closed gate must block late finalization instead of disabling CAA.
     */
    @Test
    void shutdownCannotTurnEnforcementIntoBypass() throws Exception {
        configure(true);
        engine.shutdownCAA();
        assertThrows(IllegalStateException.class, () -> finalizeIssuance());
        assertFalse(EVENTS.contains("issue"));
    }

    /**
     * Unusable stored authorization state must fail before DNS or issuer submission.
     */
    @Test
    void invalidContextPersistsOrderErrorWithoutDnsOrSubmission() throws Exception {
        configure(true);
        engine.invalidContext = true;
        try {
            ACMEException error = assertThrows(ACMEException.class, () -> finalizeIssuance());
            assertEquals("urn:ietf:params:acme:error:unauthorized", error.getError().getType());
            assertEquals(List.of("csr", "persist-invalid"), EVENTS);
        } finally {
            engine.shutdownCAA();
        }
    }

    /**
     * A wildcard CSR receives the matching wildcard authorization and canonical account URI.
     */
    @Test
    void mapsAccountOwnedAuthorizationAndWildcardContext() throws Exception {
        ACMEEngine requestEngine = requestEngine();
        ACMEAccount account = new ACMEAccount();
        account.setID("account-1");
        ACMEOrder requestOrder = new ACMEOrder();
        requestOrder.setID("order-1");
        requestOrder.setAuthzIDs(new String[] {"authz-1"});
        ACMEAuthorization authz = authorization();
        authz.setWildcard(true);
        requestEngine.getDatabase().addAuthorization(authz);
        CAARequest result =
                ACMECAAValidator.createRequest(
                        requestEngine, account, requestOrder, Set.of("*.www.example.com"));
        CAARequest.CertificateName name = result.names().get(0);
        assertTrue(name.wildcard());
        assertEquals(NAME, name.baseName());
        assertEquals(
                "https://acme.example/acme/acct/account-1",
                result.contexts().get(name).accountUri().orElseThrow().toString());
        assertEquals("dns-01", result.contexts().get(name).validationMethod().orElseThrow());
    }

    /**
     * Change one otherwise valid authorization fact at a time; none may authorize the CSR name.
     */
    @Test
    void foreignExpiredAndWrongWildcardAuthorizationsCannotSupplyContext() throws Exception {
        // Every variant starts from the same valid authorization.
        // Only the changed fact should make it unusable for this name.
        for (String state : List.of("foreign", "expired", "wildcard")) {
            ACMEEngine requestEngine = requestEngine();
            ACMEAccount account = new ACMEAccount();
            account.setID("account-1");
            ACMEOrder requestOrder = new ACMEOrder();
            requestOrder.setID("order-1");
            requestOrder.setAuthzIDs(new String[] {"authz-1"});
            ACMEAuthorization authz = authorization();
            if (state.equals("foreign")) {
                authz.setAccountID("account-2");
            }
            if (state.equals("expired")) {
                authz.setExpirationTime(new Date(1));
            }
            if (state.equals("wildcard")) {
                authz.setWildcard(true);
            }
            requestEngine.getDatabase().addAuthorization(authz);
            assertThrows(
                    IllegalArgumentException.class,
                    () ->
                            ACMECAAValidator.createRequest(
                                    requestEngine,
                                    account,
                                    requestOrder,
                                    Set.of("www.example.com")));
        }
    }

    /**
     * Two distinct successful challenge types leave method context absent for policy evaluation.
     */
    @Test
    void ambiguousSuccessfulMethodsDoNotSelectAnArbitraryBindingMethod() throws Exception {
        ACMEEngine requestEngine = requestEngine();
        ACMEAccount account = new ACMEAccount();
        account.setID("account-1");
        ACMEOrder requestOrder = new ACMEOrder();
        requestOrder.setID("order-1");
        requestOrder.setAuthzIDs(new String[] {"authz-1"});
        ACMEAuthorization authz = authorization();
        ACMEChallenge other = new ACMEChallenge();
        other.setType("http-01");
        other.setStatus("valid");
        other.setValidationTime(new Date(1));
        authz.setChallenges(List.of(authz.getChallenges().iterator().next(), other));
        requestEngine.getDatabase().addAuthorization(authz);
        CAARequest result =
                ACMECAAValidator.createRequest(
                        requestEngine, account, requestOrder, Set.of("www.example.com"));
        assertTrue(result.contexts().get(result.names().get(0)).validationMethod().isEmpty());
    }

    /**
     * Disabling CAA skips its provider and context checks while retaining ordinary CSR validation.
     */
    @Test
    void explicitDisablementStillChecksTheCsrButDoesNotBuildCaaContext() throws Exception {
        configure(false);
        engine.invalidContext = true;
        try {
            assertEquals("certificate-1", finalizeIssuance());
            assertEquals(List.of("csr", "issue"), EVENTS);
            assertEquals(0, Provider.opens);
            EVENTS.clear();
            engine.invalidCSR = true;
            assertThrows(Exception.class, () -> finalizeIssuance());
            assertEquals(List.of("csr"), EVENTS);
        } finally {
            engine.shutdownCAA();
        }
    }

    /**
     * An enabled provider loading failure leaves finalization blocked by the engine lifecycle
     * check.
     */
    @Test
    void failedPluginInitializationCannotLeaveAnIssuanceBypass() throws Exception {
        Path file = directory.resolve("missing-provider.conf");
        Files.writeString(
                file,
                "enabled=true\nissuerIdentifiers=ca.example\ndns.class=not.installed.Provider\n");
        assertThrows(DNSLookupException.class, () -> engine.initCAA(file.toString()));
        assertThrows(IllegalStateException.class, () -> finalizeIssuance());
        assertFalse(EVENTS.contains("issue"));
    }

    /**
     * Repeated initialization cannot replace the live gate; repeated shutdown closes its client
     * once.
     */
    @Test
    void initializationCannotReplaceAnActiveGateOrOpenAnotherClient() throws Exception {
        configure(true);

        try {
            assertThrows(IllegalStateException.class, () -> configure(true));
            assertEquals(1, Provider.opens);
            assertEquals("certificate-1", finalizeIssuance());
        } finally {
            engine.shutdownCAA();
            engine.shutdownCAA();
        }
        assertEquals(1, Provider.closes);
    }

    /**
     * A path I/O error must fail initialization rather than be treated as a missing optional
     * policy.
     */
    @Test
    void configurationPathErrorsCannotSilentlyDisableCaa() throws Exception {
        Path file = directory.resolve("regular-file");
        Files.writeString(file, "not a directory");
        assertThrows(IOException.class, () -> engine.initCAA(file.resolve("caa.conf").toString()));
        assertEquals(0, Provider.opens);
        assertThrows(IllegalStateException.class, () -> finalizeIssuance());
        assertFalse(EVENTS.contains("issue"));
    }

    /**
     * Each representative operational failure must produce the same blocking ACME DNS problem.
     */
    @Test
    void allDnsFailureCategoriesPersistDnsErrorsWithoutCallingTheIssuer() throws Exception {
        // Reset the engine and event trace so each failure independently
        // proves that no issuer submission follows the persisted DNS error.
        for (DNSLookupException.Reason reason :
                List.of(
                        DNSLookupException.Reason.TIMEOUT,
                        DNSLookupException.Reason.UNREACHABLE,
                        DNSLookupException.Reason.VALIDATION_FAILURE,
                        DNSLookupException.Reason.MALFORMED_RESPONSE,
                        DNSLookupException.Reason.LIMIT_EXCEEDED)) {
            prepare();
            configure(true);
            Provider.fail = true;
            Provider.failureReason = reason;
            try {
                ACMEException error = assertThrows(ACMEException.class, () -> finalizeIssuance());
                assertEquals(
                        "urn:ietf:params:acme:error:dns",
                        error.getError().getType(),
                        reason.name());
                assertEquals("invalid", order.getStatus());
                assertTrue(order.getError().contains("acme:error:dns"));
                assertNotNull(order.getExpirationTime());
                assertEquals(List.of("csr", "dns", "persist-invalid"), EVENTS);
            } finally {
                engine.shutdownCAA();
            }
        }
    }

    /**
     * A backend failure after CAA allowance must propagate without retrying or rewriting it as
     * denial.
     */
    @Test
    void aCaSubmissionFailureIsNotRetriedOrMisreportedAsCaaDenial() throws Exception {
        configure(true);
        IOException failure = new IOException("CA backend unavailable");

        engine.setIssuer(
                new ACMEIssuer() {
                    @Override
                    public String issueCertificate(PKCS10 csr) throws Exception {
                        EVENTS.add("issue");
                        throw failure;
                    }
                });
        try {
            assertSame(failure, assertThrows(IOException.class, () -> finalizeIssuance()));
            assertEquals(List.of("csr", "dns", "issue"), EVENTS);
            assertEquals("processing", order.getStatus());
        } finally {
            engine.shutdownCAA();
        }
    }

    /**
     * Extract the CN and both SANs from a signed CSR fixture, and require context for all three
     * names.
     */
    @Test
    void readsCnAndAllDnsSansFromARealCsr() throws Exception {
        ACMEEngine requestEngine = requestEngine();
        List<String> ids = new ArrayList<>();
        for (String dnsName :
                List.of("cn-only.example.com", "www.example.com", "api.example.com")) {
            ACMEAuthorization authz = authorization();
            authz.setID(dnsName);
            authz.setIdentifier(new ACMEIdentifier("dns", dnsName));
            requestEngine.getDatabase().addAuthorization(authz);
            ids.add(dnsName);
        }
        ACMEAccount account = new ACMEAccount();
        account.setID("account-1");
        ACMEOrder requestOrder = new ACMEOrder();
        requestOrder.setID("order-csr");
        requestOrder.setAuthzIDs(ids.toArray(String[]::new));
        CAARequest result =
                ACMECAAValidator.createRequest(
                        requestEngine, account, requestOrder, readCSR("caa-names.csr"));
        assertEquals(
                Set.of("cn-only.example.com.", "www.example.com.", "api.example.com."),
                result.names().stream()
                        .map(n -> n.baseName().asciiAbsoluteName())
                        .collect(java.util.stream.Collectors.toSet()));
        assertEquals(3, result.contexts().size());
    }

    /**
     * Different names use different successful methods; DNS case normalization must not mix them.
     */
    @Test
    void eachNameGetsOnlyItsOwnSuccessfulValidationMethod() throws Exception {
        ACMEEngine requestEngine = requestEngine();
        ACMEAccount account = new ACMEAccount();
        account.setID("account-1");
        ACMEAuthorization first = authorization();
        ACMEAuthorization second = authorization();
        second.setID("authz-2");
        second.setIdentifier(new ACMEIdentifier("dns", "api.example.com"));
        second.getChallenges().iterator().next().setType("http-01");
        requestEngine.getDatabase().addAuthorization(first);
        requestEngine.getDatabase().addAuthorization(second);
        ACMEOrder requestOrder = new ACMEOrder();
        requestOrder.setID("order-names");
        requestOrder.setAuthzIDs(new String[] {"authz-1", "authz-2"});
        CAARequest result =
                ACMECAAValidator.createRequest(
                        requestEngine,
                        account,
                        requestOrder,
                        Set.of("WWW.EXAMPLE.COM", "api.example.com"));
        for (CAARequest.CertificateName name : result.names()) {
            assertEquals(
                    name.baseName().equals(NAME) ? "dns-01" : "http-01",
                    result.contexts().get(name).validationMethod().orElseThrow());
        }
    }

    /**
     * One authorized SAN cannot make a second SAN with missing authorization acceptable.
     */
    @Test
    void missingAuthorizationForOneSanPreventsBuildingTheRequest() throws Exception {
        ACMEEngine requestEngine = requestEngine();
        requestEngine.getDatabase().addAuthorization(authorization());
        ACMEAccount account = new ACMEAccount();
        account.setID("account-1");
        ACMEOrder requestOrder = new ACMEOrder();
        requestOrder.setID("order");
        requestOrder.setAuthzIDs(new String[] {"authz-1", "not-in-database"});
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        ACMECAAValidator.createRequest(
                                requestEngine,
                                account,
                                requestOrder,
                                Set.of("www.example.com", "api.example.com")));
    }

    /**
     * Noncurrent or mismatched authorizations cannot establish ownership of the requested DNS name.
     */
    @Test
    void pendingWrongNameAndNonDnsAuthorizationsCannotAuthorizeTheName() throws Exception {
        for (String state : List.of("pending", "wrong-name", "ip", "no-expiration")) {
            ACMEEngine requestEngine = requestEngine();
            ACMEAuthorization authz = authorization();
            if (state.equals("pending")) {
                authz.setStatus("pending");
            }
            if (state.equals("wrong-name")) {
                authz.setIdentifier(new ACMEIdentifier("dns", "other.example.com"));
            }
            if (state.equals("ip")) {
                authz.setIdentifier(new ACMEIdentifier("ip", "www.example.com"));
            }
            if (state.equals("no-expiration")) {
                authz.setExpirationTime(null);
            }
            requestEngine.getDatabase().addAuthorization(authz);
            ACMEAccount account = new ACMEAccount();
            account.setID("account-1");
            ACMEOrder requestOrder = new ACMEOrder();
            requestOrder.setID("order");
            requestOrder.setAuthzIDs(new String[] {"authz-1"});
            assertThrows(
                    IllegalArgumentException.class,
                    () ->
                            ACMECAAValidator.createRequest(
                                    requestEngine,
                                    account,
                                    requestOrder,
                                    Set.of("www.example.com")),
                    state);
        }
    }

    /**
     * A valid authorization with unusable challenge history supplies no method-binding fact.
     */
    @Test
    void invalidMissingTimeAndFutureChallengesCannotSupplyBindingMethod() throws Exception {
        for (String state : List.of("invalid", "no-time", "future", "no-challenges")) {
            ACMEEngine requestEngine = requestEngine();
            ACMEAuthorization authz = authorization();
            ACMEChallenge challenge = authz.getChallenges().iterator().next();
            if (state.equals("invalid")) {
                challenge.setStatus("invalid");
            }
            if (state.equals("no-time")) {
                challenge.setValidationTime(null);
            }
            if (state.equals("future")) {
                challenge.setValidationTime(new Date(System.currentTimeMillis() + 60000));
            }
            if (state.equals("no-challenges")) {
                authz.setChallenges(null);
            }
            requestEngine.getDatabase().addAuthorization(authz);
            ACMEAccount account = new ACMEAccount();
            account.setID("account-1");
            ACMEOrder requestOrder = new ACMEOrder();
            requestOrder.setID("order");
            requestOrder.setAuthzIDs(new String[] {"authz-1"});
            CAARequest result =
                    ACMECAAValidator.createRequest(
                            requestEngine, account, requestOrder, Set.of("www.example.com"));
            assertTrue(
                    result.contexts().get(result.names().get(0)).validationMethod().isEmpty(),
                    state);
        }
    }

    /**
     * Repeated evidence for the same successful method still yields one unambiguous binding value.
     */
    @Test
    void duplicateSuccessfulAuthorizationsForTheSameMethodAreNotAmbiguous() throws Exception {
        ACMEEngine requestEngine = requestEngine();
        ACMEAuthorization first = authorization();
        ACMEAuthorization second = authorization();
        second.setID("authz-2");
        requestEngine.getDatabase().addAuthorization(first);
        requestEngine.getDatabase().addAuthorization(second);
        ACMEAccount account = new ACMEAccount();
        account.setID("account-1");
        ACMEOrder requestOrder = new ACMEOrder();
        requestOrder.setID("order");
        requestOrder.setAuthzIDs(new String[] {"authz-1", "authz-2"});
        CAARequest result =
                ACMECAAValidator.createRequest(
                        requestEngine, account, requestOrder, Set.of("www.example.com"));
        assertEquals(
                "dns-01",
                result.contexts().get(result.names().get(0)).validationMethod().orElseThrow());
    }

    /**
     * Public URL paths and proxy request origins must not change the published account identifier.
     */
    @Test
    void canonicalAccountUrlUsesConfiguredOriginAndDeployedContext() throws Exception {
        // Cross origin-only and path-bearing configuration with all
        // supported context shapes, including a webapp deployed at the root.
        for (String base :
                List.of(
                        "https://acme.example",
                        "https://acme.example/acme",
                        "https://acme.example/ignored/")) {
            Path config = directory.resolve("url-engine.conf");
            Files.writeString(config, "baseURL=" + base + "\n");
            engine.loadEngineConfig(config.toString());
            for (String context : List.of("acme", "custom-acme", "ROOT")) {
                engine.setID(context);
                String expected =
                        "https://acme.example"
                                + (context.equals("ROOT") ? "" : "/" + context)
                                + "/acct/account-1";
                assertEquals(
                        expected,
                        engine.getAccountURI(
                                        URI.create("http://untrusted.example/new-account"),
                                        "account-1")
                                .toString());
                assertEquals(expected, engine.getAccountURI(null, "account-1").toString());
            }
        }
    }

    /**
     * Enabled CAA needs configured account identity; disabled deployments retain registration
     * fallback.
     */
    @Test
    void enabledCaaRequiresCanonicalOriginButDisabledRegistrationRetainsRequestFallback()
            throws Exception {
        Path config = directory.resolve("no-base.conf");
        Files.writeString(config, "");
        engine.loadEngineConfig(config.toString());
        assertEquals(
                "https://acme.example/acme/acct/account-1",
                engine.getAccountURI(
                                URI.create("https://acme.example/acme/new-account"), "account-1")
                        .toString());
        assertThrows(IllegalArgumentException.class, () -> configure(true));
        assertEquals(1, Provider.closes, "Failed initialization must close its opened provider");
        assertThrows(IllegalStateException.class, () -> engine.getAccountURI(null, "account-1"));
        configure(false);
        try {
            assertEquals("certificate-1", finalizeIssuance());
        } finally {
            engine.shutdownCAA();
        }
    }

    /**
     * Reject invalid configured origins before the engine can accept finalization.
     * Each failure must close its opened provider exactly once and leave DNS and
     * issuer submission untouched.
     */
    @Test
    void invalidAccountOriginsFailCaaInitializationAndCloseTheProvider() throws Exception {
        for (String origin : List.of(
                "ftp://acme.example",
                "https://user@acme.example",
                "https:/missing-host")) {
            // Reset the engine and counters so every variant independently
            // proves startup rejection, cleanup and blocked finalization.
            prepare();
            Path config = directory.resolve("invalid-origin-engine.conf");
            Files.writeString(config, "baseURL=" + origin + "\n");
            engine.loadEngineConfig(config.toString());

            IllegalArgumentException error = assertThrows(
                    IllegalArgumentException.class, () -> configure(true), origin);
            assertEquals("Invalid ACME account URL origin", error.getMessage());
            assertThrows(IllegalArgumentException.class, () -> engine.getAccountURI(
                    URI.create("https://request.example/new-account"), "account-1"), origin);
            assertEquals(1, Provider.opens, origin);
            assertEquals(1, Provider.closes, origin);
            assertThrows(IllegalStateException.class, () -> finalizeIssuance(), origin);
            assertFalse(EVENTS.contains("dns"), origin);
            assertFalse(EVENTS.contains("issue"), origin);

            engine.shutdownCAA();
            assertEquals(1, Provider.closes, "Shutdown must not close the failed client twice");
        }
    }

    /**
     * URL parsing accepts an unescaped space that URI conversion must reject.
     * A checked syntax exception must release the provider just like an invalid
     * origin, and corrected configuration must permit initialization afterward.
     */
    @Test
    void invalidAccountUriSyntaxClosesTheProviderAndAllowsCorrectedConfiguration() throws Exception {
        Path config = directory.resolve("invalid-uri-engine.conf");
        Files.writeString(config, "baseURL=https://acme.example/bad path\n");
        engine.loadEngineConfig(config.toString());

        assertThrows(URISyntaxException.class, () -> configure(true));
        assertEquals(1, Provider.opens);
        assertEquals(1, Provider.closes);
        assertThrows(IllegalStateException.class, () -> finalizeIssuance());
        assertFalse(EVENTS.contains("dns"));
        assertFalse(EVENTS.contains("issue"));

        Files.writeString(config, "baseURL=https://acme.example/acme\n");
        engine.loadEngineConfig(config.toString());
        EVENTS.clear();
        configure(true);
        try {
            assertEquals(2, Provider.opens);
            assertEquals("certificate-1", finalizeIssuance());
            assertEquals(List.of("csr", "dns", "issue"), EVENTS);
        } finally {
            engine.shutdownCAA();
        }
        assertEquals(2, Provider.closes);
    }

    /**
     * Drives the servlet's explicit validation/issuance steps without the HTTP/JWS handler.
     */
    private String finalizeIssuance() throws Exception {
        engine.validateCSR(issuanceAccount, order, issuanceCSR);
        engine.validateCAA(issuanceAccount, order, issuanceCSR);
        return engine.getIssuer().issueCertificate(issuanceCSR);
    }

    /**
     * Public CSR fixtures contain no private keys; signature verification is a separate stage.
     */
    private PKCS10 readCSR(String resource) throws Exception {
        String pem;
        try (InputStream stream = getClass().getResourceAsStream(resource)) {
            assertNotNull(stream);
            pem = new String(stream.readAllBytes(), StandardCharsets.US_ASCII);
        }
        byte[] der =
                Base64.getMimeDecoder()
                        .decode(
                                pem.replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                                        .replace("-----END CERTIFICATE REQUEST-----", ""));
        return new PKCS10(der, false);
    }

    /**
     * Creates a standalone host for context mapping without opening a CAA provider.
     */
    private ACMEEngine requestEngine() throws Exception {
        ACMEEngine result = new ACMEEngine();
        result.setID("acme");
        Path file = directory.resolve("engine.conf");
        Files.writeString(file, "baseURL=https://acme.example/acme\n");
        result.loadEngineConfig(file.toString());
        result.setDatabase(new InMemoryDatabase());
        return result;
    }

    /**
     * Creates one current account-owned DNS authorization with a successful DNS-01 challenge.
     */
    private static ACMEAuthorization authorization() {
        ACMEAuthorization authz = new ACMEAuthorization();
        authz.setID("authz-1");
        authz.setAccountID("account-1");
        authz.setStatus("valid");
        authz.setIdentifier(new ACMEIdentifier("dns", "www.example.com"));
        authz.setExpirationTime(new Date(System.currentTimeMillis() + 60000));
        ACMEChallenge challenge = new ACMEChallenge();
        challenge.setType("dns-01");
        challenge.setStatus("valid");
        challenge.setValidationTime(new Date(1));
        authz.setChallenges(List.of(challenge));
        return authz;
    }

    /**
     * Loads the test provider through the same policy-file path as an installed ACME service.
     */
    private void configure(boolean enabled) throws Exception {
        Path path = directory.resolve("caa.conf");
        Files.writeString(
                path,
                "enabled="
                        + enabled
                        + "\nissuerIdentifiers=ca.example\ndns.class="
                        + Provider.class.getName()
                        + "\n");
        engine.initCAA(path.toString());
    }

    /**
     * Records engine boundaries while isolating CA submission and order persistence.
     */
    private static final class Engine extends ACMEEngine {
        boolean invalidCSR;
        boolean invalidContext;

        @Override
        public void validateCSR(ACMEAccount account, ACMEOrder order, PKCS10 csr) throws Exception {
            EVENTS.add("csr");
            if (invalidCSR) {
                throw new Exception("invalid CSR fixture");
            }
            if (invalidContext) {
                getDatabase().getAuthorization("authz-1").setStatus("pending");
            }
        }

        @Override
        public ACMEPolicy getPolicy() {
            return new ACMEPolicy(new ACMEPolicyConfig());
        }

        @Override
        public void updateOrder(ACMEAccount account, ACMEOrder order) {
            EVENTS.add("persist-" + order.getStatus());
        }
    }

    /**
     * Configuration-loadable fixture belongs only in the test classpath.
     */
    public static final class Provider implements CAADNSClientProvider, CAADNSClient {
        static String value;
        static boolean fail;
        static int opens;
        static int closes;
        static DNSLookupException.Reason failureReason;

        @Override
        public CAADNSClient open(Config config) {
            opens++;
            return this;
        }

        @Override
        public LookupResult resolveCaa(DNSDomainName name, LookupBudget budget)
                throws DNSLookupException {
            EVENTS.add("dns");
            budget.reserveQuery();
            if (fail)
                throw new DNSLookupException(
                        new DNSLookupException.Failure(
                                failureReason, "fixture failure", List.of()));
            return new LookupResult(
                    name,
                    name,
                    LookupKind.RRSET,
                    List.of(
                            new CAARecord(
                                    name,
                                    60,
                                    0,
                                    "issue",
                                    value.getBytes(StandardCharsets.US_ASCII))),
                    List.of(),
                    List.of(
                            new ResponseEvidence(
                                    "fixture",
                                    name,
                                    0,
                                    false,
                                    ValidationStatus.UNCLASSIFIED,
                                    "fixture",
                                    Optional.empty())),
                    Optional.empty());
        }

        @Override
        public void close() {
            closes++;
        }
    }
}
