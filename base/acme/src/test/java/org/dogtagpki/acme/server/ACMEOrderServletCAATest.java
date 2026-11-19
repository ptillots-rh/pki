// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEException;
import org.dogtagpki.acme.ACMEIdentifier;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.JWK;
import org.dogtagpki.acme.JWS;
import org.dogtagpki.acme.caa.CAADNSClient;
import org.dogtagpki.acme.caa.CAADNSClientProvider;
import org.dogtagpki.acme.caa.DNSDomainName;
import org.dogtagpki.acme.caa.DNSLookupException;
import org.dogtagpki.acme.database.InMemoryDatabase;
import org.dogtagpki.acme.issuer.ACMEIssuer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.InitializationValues;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Handler;
import java.util.logging.LogRecord;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Tests CAA enforcement in the actual ACME finalization servlet.
 *
 * Requests use real CSR fixtures and signature verification. HTTP request and
 * response doubles avoid a servlet container, while the recording engine
 * replaces JWS authentication, persistence and CA submission. Assertions pin
 * the CSR -> CAA -> issuer sequence, persisted order outcomes, canonical account
 * URLs and operator-facing CAA logs. Full HTTP/JWS and CA enrollment remain the
 * responsibility of the installed enrollment harness.
 */
public class ACMEOrderServletCAATest {
    @TempDir Path directory;
    private RecordingEngine engine;
    private ACMEEngine previousEngine;
    private final List<String> logs = new ArrayList<>();
    private final Handler logCapture =
            new Handler() {
                @Override
                public void publish(LogRecord record) {
                    logs.add(record.getMessage());
                }

                @Override
                public void flush() {}

                @Override
                public void close() {}
            };

    @BeforeAll
    static void initializeSignatureVerification() throws Exception {
        if (!CryptoManager.isInitialized()) {
            InitializationValues values = new InitializationValues("");
            values.noCertDB = true;
            values.noModDB = true;
            CryptoManager.initialize(values);
        }
    }

    /**
     * Starts each case with one current account, authorization and CSR.
     */
    @BeforeEach
    void prepare() throws Exception {
        previousEngine = ACMEEngine.INSTANCE;
        engine = new RecordingEngine();
        engine.setID("acme");
        Path config = directory.resolve("engine.conf");
        // Origin-only configuration must produce the actual /acme account URL.
        Files.writeString(config, "baseURL=https://acme.example\n");
        engine.loadEngineConfig(config.toString());

        engine.setDatabase(new InMemoryDatabase());
        engine.account.setID("account-1");
        engine.account.setStatus("valid");
        engine.order.setID("order-1");
        engine.order.setStatus("ready");
        engine.order.setAuthzIDs(new String[] {"authz-1"});
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
        engine.getDatabase().addAuthorization(authz);

        engine.setIssuer(
                new ACMEIssuer() {
                    @Override
                    public String issueCertificate(PKCS10 csr) {
                        engine.events.add("issue");
                        return "certificate-1";
                    }
                });
        Provider.engine = engine;
        Provider.value =
                "ca.example;accounturi=https://acme.example/acme/acct/account-1;validationmethods=dns-01";
        Provider.failure = null;
        Provider.rcode = 0;
        Provider.extendedError = Optional.empty();
        java.util.logging.Logger.getLogger(ACMECAAValidator.class.getName()).addHandler(logCapture);
    }

    @AfterEach
    void close() {
        engine.shutdownCAA();
        ACMEEngine.INSTANCE = previousEngine;
        Provider.engine = null;
        java.util.logging.Logger.getLogger(ACMECAAValidator.class.getName())
                .removeHandler(logCapture);
    }

    /**
     * Exercise real finalization and CSR verification, then check event ordering and bounded CAA
     * logs.
     */
    @Test
    void servletChecksCsrAndCaaBeforeIssuingAndPersistingValidOrder() throws Exception {
        configure(true);
        finalizeOrder("caa-issuance.csr");
        // The issuer must appear after DNS, and valid persistence after
        // the issuer. Earlier HTTP/JWS checks still run in their normal order.
        assertEquals(
                List.of(
                        "nonce",
                        "jws",
                        "persist-processing",
                        "csr",
                        "dns",
                        "issue",
                        "persist-valid"),
                engine.events);
        assertEquals("valid", engine.order.getStatus());
        assertEquals("certificate-1", engine.order.getCertID());
        assertTrue(hasLogMessage("evaluation=ALLOW"));
        assertTrue(hasLogMessage("submission=permitted"));
        assertFalse(
                hasLogMessage("/acct/"),
                "CAA logs must not contain account URLs");
    }

    /**
     * The actual servlet must persist denial and return without attaching a certificate to the
     * order.
     */
    @Test
    void servletDenialPersistsInvalidOrderAndNeverInvokesIssuer() throws Exception {
        configure(true);
        Provider.value = ";";
        ACMEException error =
                assertThrows(ACMEException.class, () -> finalizeOrder("caa-issuance.csr"));
        assertEquals("urn:ietf:params:acme:error:caa", error.getError().getType());
        assertEquals(
                List.of("nonce", "jws", "persist-processing", "csr", "dns", "persist-invalid"),
                engine.events);
        assertEquals("invalid", engine.order.getStatus());
        assertNull(engine.order.getCertID());
        assertTrue(engine.order.getError().contains("acme:error:caa"));
    }

    /**
     * A timeout retains its typed reason and partial DNS observation while preventing issuer
     * submission.
     */
    @Test
    void servletDnsFailurePreservesTypedOperationalReasonAndBlocksIssuer() throws Exception {
        configure(true);
        Provider.failure = DNSLookupException.Reason.TIMEOUT;
        ACMEException error =
                assertThrows(ACMEException.class, () -> finalizeOrder("caa-issuance.csr"));
        assertEquals("urn:ietf:params:acme:error:dns", error.getError().getType());
        assertEquals("invalid", engine.order.getStatus());
        assertNull(engine.order.getCertID());
        assertFalse(engine.events.contains("issue"));
        assertTrue(hasLogMessage("dnsFailure=TIMEOUT"));
        assertTrue(hasLogMessage("dnssec=UNTRUSTED"));
        assertTrue(hasLogMessage("submission=blocked"));
        assertFalse(hasLogMessage("submission=permitted"));
    }

    /**
     * Account binding failures should identify the failed restriction without
     * publishing either the requesting account URI or the DNS record value.
     */
    @Test
    void accountMismatchHasItsOwnLogReason() throws Exception {
        configure(true);
        Provider.value = "ca.example;accounturi=https://acme.example/acme/acct/other-account";

        assertThrows(ACMEException.class, () -> finalizeOrder("caa-issuance.csr"));

        assertTrue(hasLogMessage("reason=ACCOUNT_NOT_AUTHORIZED"));
        assertTrue(hasLogMessage("submission=blocked reason=EVALUATION evaluation=DENY"));
        assertFalse(hasLogMessage("other-account"));
        assertFalse(hasLogMessage("/acct/"));
        assertFalse(engine.events.contains("issue"));
    }

    /**
     * A method mismatch should show the successful method supplied by ACME,
     * allowing an operator to distinguish it from an issuer mismatch.
     */
    @Test
    void methodMismatchLogsTheMethodUsed() throws Exception {
        configure(true);
        Provider.value = "ca.example;validationmethods=http-01";

        assertThrows(ACMEException.class, () -> finalizeOrder("caa-issuance.csr"));

        assertTrue(hasLogMessage("reason=VALIDATION_METHOD_NOT_AUTHORIZED"));
        assertTrue(hasLogMessage("method=dns-01"));
        assertFalse(engine.events.contains("issue"));
    }

    /**
     * Expired ownership facts must stop issuance before DNS and produce a safe
     * context category rather than logging stored authorization contents.
     */
    @Test
    void missingAuthorizationLogsContextFailureBeforeDns() throws Exception {
        configure(true);
        engine.getDatabase().getAuthorization("authz-1").setExpirationTime(new Date(1));

        ACMEException error = assertThrows(ACMEException.class,
                () -> finalizeOrder("caa-issuance.csr"));

        assertEquals("urn:ietf:params:acme:error:unauthorized", error.getError().getType());
        assertTrue(hasLogMessage("submission=blocked reason=CONTEXT contextFailure=MISSING_AUTHORIZATION"));
        assertFalse(hasLogMessage("/acct/"));
        assertFalse(engine.events.contains("dns"));
        assertFalse(engine.events.contains("issue"));
    }

    /**
     * DNSSEC errors keep their numeric codes and gain readable labels. The
     * resolver's optional diagnostic text is untrusted and stays out of logs.
     */
    @Test
    void dnssecFailureLogsCodeNamesWithoutDiagnosticText() throws Exception {
        configure(true);
        Provider.failure = DNSLookupException.Reason.VALIDATION_FAILURE;
        Provider.rcode = 2;
        Provider.extendedError = Optional.of(new CAADNSClient.ExtendedError(
                6, Optional.of("private resolver diagnostic\ninjected line")));

        assertThrows(ACMEException.class, () -> finalizeOrder("caa-issuance.csr"));

        assertTrue(hasLogMessage("rcode=2 rcodeName=SERVFAIL"));
        assertTrue(hasLogMessage("ede=6 edeName=DNSSEC_BOGUS"));
        assertFalse(hasLogMessage("private resolver diagnostic"));
        assertFalse(hasLogMessage("injected line"));
        assertFalse(engine.events.contains("issue"));
    }

    /**
     * Unknown protocol codes must remain visible numerically, even when this
     * version of the host has no mnemonic for them.
     */
    @Test
    void unknownDnsCodesRemainVisible() throws Exception {
        configure(true);
        Provider.failure = DNSLookupException.Reason.VALIDATION_FAILURE;
        Provider.rcode = 4095;
        Provider.extendedError = Optional.of(new CAADNSClient.ExtendedError(65535, Optional.empty()));

        assertThrows(ACMEException.class, () -> finalizeOrder("caa-issuance.csr"));

        assertTrue(hasLogMessage("rcode=4095 rcodeName=UNKNOWN"));
        assertTrue(hasLogMessage("ede=65535 edeName=UNKNOWN"));
    }

    /**
     * Startup should expose the endpoint needed to diagnose an outage, while
     * omitting unrelated provider settings and flattening embedded newlines.
     */
    @Test
    void startupLogsOnlyAllowlistedConfigurationOnOneLine() throws Exception {
        configure(true, "dns.settings.server=127.0.0.1\n"
                + "dns.settings.port=1053\n"
                + "dns.settings.password=provider-secret\n"
                + "issuerIdentifiers=ca.example,\\nca2.example\n");

        assertTrue(hasLogMessage("configuration provider=" + Provider.class.getName()));
        assertTrue(hasLogMessage("issuers=ca.example, ca2.example resolver=127.0.0.1 port=1053"));
        assertFalse(hasLogMessage("provider-secret"));
        assertFalse(hasLogMessage("\n"));
    }

    /**
     * A validly encoded CSR with the wrong order names must fail before any DNS query.
     */
    @Test
    void mismatchedCsrNeverReachesCaaOrIssuer() throws Exception {
        configure(true);
        assertThrows(Exception.class, () -> finalizeOrder("caa-names.csr"));
        assertEquals(List.of("nonce", "jws", "persist-processing", "csr"), engine.events);
    }

    /**
     * The servlet continues its normal issuance and persistence sequence when CAA is explicitly
     * disabled.
     */
    @Test
    void disabledCaaPreservesNormalServletIssuance() throws Exception {
        configure(false);
        finalizeOrder("caa-issuance.csr");
        assertEquals(
                List.of("nonce", "jws", "persist-processing", "csr", "issue", "persist-valid"),
                engine.events);
    }

    /**
     * Registration behind a proxy publishes the exact account URI later supplied to CAA policy.
     */
    @Test
    void accountRegistrationPublishesTheSameCanonicalUriUsedForBinding() throws Exception {
        Map<String, String> headers = new HashMap<String, String>();
        ACMENewAccountServlet servlet = new ACMENewAccountServlet();
        servlet.engine = engine;
        servlet.updateAccount(request("/new-account", jws("{}")), response(headers));
        assertEquals(engine.getAccountURI(null, "account-1").toString(), headers.get("Location"));
        assertEquals("https://acme.example/acme/acct/account-1", headers.get("Location"));
    }

    /**
     * Searches only the CAA logger messages captured during this request.
     */
    private boolean hasLogMessage(String fragment) {
        for (String message : logs) {
            if (message.contains(fragment)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Loads the test provider through the same policy-file path as an installed ACME service.
     */
    private void configure(boolean enabled) throws Exception {
        configure(enabled, "");
    }

    private void configure(boolean enabled, String extraSettings) throws Exception {
        Path config = directory.resolve("caa.conf");
        Files.writeString(
                config,
                "enabled="
                        + enabled
                        + "\nissuerIdentifiers=ca.example\ndns.class="
                        + Provider.class.getName()
                        + "\n" + extraSettings);
        engine.initCAA(config.toString());
    }

    /**
     * Builds an ACME finalize payload from a real CSR and invokes the actual servlet handler.
     */
    private void finalizeOrder(String csrResource) throws Exception {
        String pem;
        try (InputStream input = getClass().getResourceAsStream(csrResource)) {
            assertNotNull(input);
            pem = new String(input.readAllBytes(), StandardCharsets.US_ASCII);
        }
        byte[] csr =
                Base64.getMimeDecoder()
                        .decode(
                                pem.replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                                        .replace("-----END CERTIFICATE REQUEST-----", ""));
        String payload =
                "{\"csr\":\"" + Base64.getUrlEncoder().withoutPadding().encodeToString(csr) + "\"}";
        ACMEOrderServlet servlet = new ACMEOrderServlet();
        servlet.engine = engine;
        servlet.finalizeOrder(
                request("/order-1/finalize", jws(payload)), response(new HashMap<>()));
    }

    /**
     * Encodes the handler input; the recording engine replaces JWS authentication, not CSR
     * verification.
     */
    private String jws(String payload) throws Exception {
        JWS jws = new JWS();
        String header =
                "{\"kid\":\"https://acme.example/acme/acct/account-1\",\"nonce\":\"test\",\"alg\":\"RS256\"}";
        jws.setProtectedHeader(
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(header.getBytes(StandardCharsets.UTF_8)));
        jws.setPayload(
                Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(payload.getBytes(StandardCharsets.UTF_8)));
        return jws.toJSON();
    }

    /**
     * Supplies only the HTTP request methods used by these handlers; unexpected access fails the
     * test.
     */
    private HttpServletRequest request(String path, String body) {
        // Implement the small servlet interface surface needed here. Each
        // unexpected method fails visibly instead of returning a mock default.
        return (HttpServletRequest)
                Proxy.newProxyInstance(
                        getClass().getClassLoader(),
                        new Class<?>[] {HttpServletRequest.class},
                        (proxy, method, args) ->
                                switch (method.getName()) {
                                    case "getPathInfo" -> path;
                                    case "getContextPath" -> "/acme";
                                    case "getRequestURL" ->
                                            new StringBuffer(
                                                    "http://internal-proxy.example/acme" + path);
                                    case "getReader" -> new BufferedReader(new StringReader(body));
                                    default ->
                                            throw new AssertionError(
                                                    "Unexpected request method: "
                                                            + method.getName());
                                });
    }

    /**
     * Captures headers and accepts the response writer without a servlet container.
     */
    private HttpServletResponse response(Map<String, String> headers) {
        PrintWriter writer = new PrintWriter(new StringWriter());
        return (HttpServletResponse)
                Proxy.newProxyInstance(
                        getClass().getClassLoader(),
                        new Class<?>[] {HttpServletResponse.class},
                        (proxy, method, args) -> {
                            switch (method.getName()) {
                                case "getWriter":
                                    return writer;
                                case "setHeader", "addHeader":
                                    headers.put((String) args[0], (String) args[1]);
                                    return null;
                                case "setStatus":
                                    return null;
                                default:
                                    throw new AssertionError(
                                            "Unexpected response method: " + method.getName());
                            }
                        });
    }

    /**
     * Replaces HTTP authentication and persistence boundaries while retaining actual CSR
     * validation.
     */
    private static final class RecordingEngine extends ACMEEngine {
        final ACMEAccount account = new ACMEAccount();
        final ACMEOrder order = new ACMEOrder();
        final List<String> events = new ArrayList<>();

        @Override
        public void validateNonce(String value) {
            events.add("nonce");
        }

        @Override
        public void validateJWS(JWS jws, String algorithm, JWK key) {
            events.add("jws");
        }

        @Override
        public String generateThumbprint(JWK key) {
            return account.getID();
        }

        @Override
        public ACMEAccount getAccount(String id) {
            assertEquals(account.getID(), id);
            return account;
        }

        @Override
        public ACMEAccount getAccount(String id, boolean validate) {
            return getAccount(id);
        }

        @Override
        public ACMEOrder getOrder(ACMEAccount account, String id) {
            assertEquals(order.getID(), id);
            return order;
        }

        @Override
        public void updateOrder(ACMEAccount account, ACMEOrder order) {
            events.add("persist-" + order.getStatus());
        }

        @Override
        public void validateCSR(ACMEAccount account, ACMEOrder order, PKCS10 csr) throws Exception {
            events.add("csr");
            super.validateCSR(account, order, csr);
        }

        @Override
        public ACMEPolicy getPolicy() {
            return new ACMEPolicy(new ACMEPolicyConfig());
        }

        @Override
        public ACMENonce createNonce() {
            ACMENonce nonce = new ACMENonce();
            nonce.setID("next");
            return nonce;
        }
    }

    /**
     * Deterministic DNS provider loaded through the real configuration path.
     */
    public static final class Provider implements CAADNSClientProvider, CAADNSClient {
        static RecordingEngine engine;
        static String value;
        static DNSLookupException.Reason failure;
        static int rcode;
        static Optional<CAADNSClient.ExtendedError> extendedError;

        @Override
        public CAADNSClient open(Config config) {
            return this;
        }

        @Override
        public void close() {}

        @Override
        public LookupResult resolveCaa(DNSDomainName name, LookupBudget budget)
                throws DNSLookupException {
            engine.events.add("dns");
            budget.reserveQuery();
            ResponseEvidence observation =
                    new ResponseEvidence(
                            "fixture",
                            name,
                            rcode,
                            false,
                            failure == null
                                    ? ValidationStatus.UNCLASSIFIED
                                    : ValidationStatus.UNTRUSTED,
                            "fixture",
                            extendedError);
            if (failure != null) {
                throw new DNSLookupException(
                        new DNSLookupException.Failure(
                                failure, "fixture error", List.of(observation)));
            }
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
                    List.of(observation),
                    Optional.empty());
        }
    }
}
