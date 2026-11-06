// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later
package org.dogtagpki.acme.server;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.Date;
import java.util.Base64;
import java.io.IOException;

import org.dogtagpki.acme.ACMEAccount;
import org.dogtagpki.acme.ACMEException;
import org.dogtagpki.acme.ACMEOrder;
import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEIdentifier;
import org.dogtagpki.acme.database.InMemoryDatabase;
import org.dogtagpki.acme.caa.CAADNSClient;
import org.dogtagpki.acme.caa.CAADNSClientProvider;
import org.dogtagpki.acme.caa.DNSDomainName;
import org.dogtagpki.acme.caa.DNSLookupException;
import org.dogtagpki.acme.issuer.ACMEIssuer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;

/** Tests the actual ACME engine gate with a recording issuer and deterministic DNS provider. */
public class ACMEEngineCAATest {
    @TempDir Path directory;
    private static final List<String> EVENTS = new ArrayList<>();
    private static final DNSDomainName NAME = new DNSDomainName("www.example.com.");
    private Engine engine;
    private ACMEOrder order;
    private ACMEAccount issuanceAccount;
    private PKCS10 issuanceCSR;
    @BeforeEach void prepare() throws Exception {
        EVENTS.clear(); Provider.value = "ca.example"; Provider.fail = false;
        Provider.opens = 0; Provider.closes = 0;
        Provider.failureReason = DNSLookupException.Reason.RCODE_FAILURE;
        engine = new Engine(); order = new ACMEOrder(); order.setID("order-1"); order.setStatus("processing");
        Path engineConfig = directory.resolve("issuance-engine.conf");
        Files.writeString(engineConfig, "baseURL=https://acme.example/acme\n");
        engine.loadEngineConfig(engineConfig.toString());
        issuanceAccount = new ACMEAccount(); issuanceAccount.setID("account-1");
        issuanceCSR = readCSR("caa-issuance.csr");
        order.setAccountID(issuanceAccount.getID()); order.setAuthzIDs(new String[] {"authz-1"});
        engine.setDatabase(new InMemoryDatabase()); engine.getDatabase().addAuthorization(authorization());
        engine.setIssuer(new ACMEIssuer() {
            @Override public String issueCertificate(PKCS10 csr) { EVENTS.add("issue"); return "certificate-1"; }
        });
    }

    @Test void allowRunsAfterCsrValidationBeforeIssuerSubmission() throws Exception {
        configure(true);
        try {
            assertEquals("certificate-1", finalizeIssuance());
            assertEquals(List.of("csr", "dns", "issue"), EVENTS);
        } finally { engine.shutdownCAA(); }
    }

    @Test void denialPersistsInvalidOrderAndNeverCallsIssuer() throws Exception {
        configure(true); Provider.value = ";";
        try {
            ACMEException error = assertThrows(ACMEException.class, () -> finalizeIssuance());
            assertEquals("urn:ietf:params:acme:error:caa", error.getError().getType());
            assertEquals("invalid", order.getStatus());
            assertTrue(order.getError().contains("acme:error:caa"));
            assertEquals(List.of("csr", "dns", "persist-invalid"), EVENTS);
        } finally { engine.shutdownCAA(); }
    }

    @Test void dnsFailurePersistsInvalidOrderAndNeverCallsIssuer() throws Exception {
        configure(true); Provider.fail = true;
        try {
            ACMEException error = assertThrows(ACMEException.class, () -> finalizeIssuance());
            assertEquals("urn:ietf:params:acme:error:dns", error.getError().getType());
            assertEquals(List.of("csr", "dns", "persist-invalid"), EVENTS);
        } finally { engine.shutdownCAA(); }
    }

    @Test void missingConfigurationDisablesCaaWithoutLoadingAnyProvider() throws Exception {
        engine.initCAA(directory.resolve("does-not-exist.conf").toString());
        try {
            assertEquals("certificate-1", finalizeIssuance());
            assertEquals(List.of("csr", "issue"), EVENTS);
        } finally { engine.shutdownCAA(); }
    }

    @Test void invalidCsrDoesNotReachDnsOrIssuer() throws Exception {
        configure(true); engine.invalidCSR = true;
        try {
            assertThrows(Exception.class, () -> finalizeIssuance());
            assertEquals(List.of("csr"), EVENTS);
        } finally { engine.shutdownCAA(); }
    }

    @Test void shutdownCannotTurnEnforcementIntoBypass() throws Exception {
        configure(true); engine.shutdownCAA();
        assertThrows(IllegalStateException.class, () -> finalizeIssuance());
        assertFalse(EVENTS.contains("issue"));
    }

    @Test void invalidContextPersistsOrderErrorWithoutDnsOrSubmission() throws Exception {
        configure(true); engine.invalidContext = true;
        try {
            ACMEException error = assertThrows(ACMEException.class, () -> finalizeIssuance());
            assertEquals("urn:ietf:params:acme:error:unauthorized", error.getError().getType());
            assertEquals(List.of("csr", "persist-invalid"), EVENTS);
        } finally { engine.shutdownCAA(); }
    }

    @Test void mapsAccountOwnedAuthorizationAndWildcardContext() throws Exception {
        ACMEEngine requestEngine = requestEngine();
        ACMEAccount account = new ACMEAccount(); account.setID("account-1");
        ACMEOrder requestOrder = new ACMEOrder(); requestOrder.setID("order-1"); requestOrder.setAuthzIDs(new String[] {"authz-1"});
        ACMEAuthorization authz = authorization(); authz.setWildcard(true);
        requestEngine.getDatabase().addAuthorization(authz);
        var result = ACMECAAValidator.createRequest(requestEngine, account, requestOrder, Set.of("*.www.example.com"));
        var name = result.names().get(0);
        assertTrue(name.wildcard()); assertEquals(NAME, name.baseName());
        assertEquals("https://acme.example/acme/acct/account-1", result.contexts().get(name).accountUri().orElseThrow().toString());
        assertEquals("dns-01", result.contexts().get(name).validationMethod().orElseThrow());
    }

    @Test void foreignExpiredAndWrongWildcardAuthorizationsCannotSupplyContext() throws Exception {
        for (String state : List.of("foreign", "expired", "wildcard")) {
            ACMEEngine requestEngine = requestEngine();
            ACMEAccount account = new ACMEAccount(); account.setID("account-1");
            ACMEOrder requestOrder = new ACMEOrder(); requestOrder.setID("order-1"); requestOrder.setAuthzIDs(new String[] {"authz-1"});
            ACMEAuthorization authz = authorization();
            if (state.equals("foreign")) authz.setAccountID("account-2");
            if (state.equals("expired")) authz.setExpirationTime(new Date(1));
            if (state.equals("wildcard")) authz.setWildcard(true);
            requestEngine.getDatabase().addAuthorization(authz);
            assertThrows(IllegalArgumentException.class,
                    () -> ACMECAAValidator.createRequest(requestEngine, account, requestOrder, Set.of("www.example.com")));
        }
    }

    @Test void ambiguousSuccessfulMethodsDoNotSelectAnArbitraryBindingMethod() throws Exception {
        ACMEEngine requestEngine = requestEngine();
        ACMEAccount account = new ACMEAccount(); account.setID("account-1");
        ACMEOrder requestOrder = new ACMEOrder(); requestOrder.setID("order-1"); requestOrder.setAuthzIDs(new String[] {"authz-1"});
        ACMEAuthorization authz = authorization();
        ACMEChallenge other = new ACMEChallenge(); other.setType("http-01"); other.setStatus("valid"); other.setValidationTime(new Date(1));
        authz.setChallenges(List.of(authz.getChallenges().iterator().next(), other));
        requestEngine.getDatabase().addAuthorization(authz);
        var result = ACMECAAValidator.createRequest(requestEngine, account, requestOrder, Set.of("www.example.com"));
        assertTrue(result.contexts().get(result.names().get(0)).validationMethod().isEmpty());
    }

    @Test void explicitDisablementStillChecksTheCsrButDoesNotBuildCaaContext() throws Exception {
        configure(false); engine.invalidContext = true;
        try {
            assertEquals("certificate-1", finalizeIssuance());
            assertEquals(List.of("csr", "issue"), EVENTS);
            assertEquals(0, Provider.opens);
            EVENTS.clear(); engine.invalidCSR = true;
            assertThrows(Exception.class, () -> finalizeIssuance());
            assertEquals(List.of("csr"), EVENTS);
        } finally { engine.shutdownCAA(); }
    }

    @Test void failedPluginInitializationCannotLeaveAnIssuanceBypass() throws Exception {
        Path file = directory.resolve("missing-provider.conf");
        Files.writeString(file, "enabled=true\nissuerIdentifiers=ca.example\ndns.class=not.installed.Provider\n");
        assertThrows(DNSLookupException.class, () -> engine.initCAA(file.toString()));
        assertThrows(IllegalStateException.class, () -> finalizeIssuance());
        assertFalse(EVENTS.contains("issue"));
    }

    @Test void initializationCannotReplaceAnActiveGateOrOpenAnotherClient() throws Exception {
        configure(true);
        try {
            assertThrows(IllegalStateException.class, () -> configure(true));
            assertEquals(1, Provider.opens);
            assertEquals("certificate-1", finalizeIssuance());
        } finally { engine.shutdownCAA(); engine.shutdownCAA(); }
        assertEquals(1, Provider.closes);
    }

    @Test void configurationPathErrorsCannotSilentlyDisableCaa() throws Exception {
        Path file = directory.resolve("regular-file");
        Files.writeString(file, "not a directory");
        assertThrows(IOException.class, () -> engine.initCAA(file.resolve("caa.conf").toString()));
        assertEquals(0, Provider.opens);
        assertThrows(IllegalStateException.class,
                () -> finalizeIssuance());
        assertFalse(EVENTS.contains("issue"));
    }

    @Test void allDnsFailureCategoriesPersistDnsErrorsWithoutCallingTheIssuer() throws Exception {
        for (var reason : List.of(DNSLookupException.Reason.TIMEOUT, DNSLookupException.Reason.UNREACHABLE,
                DNSLookupException.Reason.VALIDATION_FAILURE, DNSLookupException.Reason.MALFORMED_RESPONSE,
                DNSLookupException.Reason.LIMIT_EXCEEDED)) {
            prepare(); configure(true); Provider.fail = true; Provider.failureReason = reason;
            try {
                var error = assertThrows(ACMEException.class, () -> finalizeIssuance());
                assertEquals("urn:ietf:params:acme:error:dns", error.getError().getType(), reason.name());
                assertEquals("invalid", order.getStatus());
                assertTrue(order.getError().contains("acme:error:dns"));
                assertNotNull(order.getExpirationTime());
                assertEquals(List.of("csr", "dns", "persist-invalid"), EVENTS);
            } finally { engine.shutdownCAA(); }
        }
    }

    @Test void aCaSubmissionFailureIsNotRetriedOrMisreportedAsCaaDenial() throws Exception {
        configure(true);
        var failure = new IOException("CA backend unavailable");
        engine.setIssuer(new ACMEIssuer() {
            @Override public String issueCertificate(PKCS10 csr) throws Exception { EVENTS.add("issue"); throw failure; }
        });
        try {
            assertSame(failure, assertThrows(IOException.class,
                    () -> finalizeIssuance()));
            assertEquals(List.of("csr", "dns", "issue"), EVENTS);
            assertEquals("processing", order.getStatus());
        } finally { engine.shutdownCAA(); }
    }

    @Test void readsCnAndAllDnsSansFromARealCsr() throws Exception {
        ACMEEngine requestEngine = requestEngine();
        var ids = new ArrayList<String>();
        for (String dnsName : List.of("cn-only.example.com", "www.example.com", "api.example.com")) {
            var authz = authorization(); authz.setID(dnsName);
            authz.setIdentifier(new ACMEIdentifier("dns", dnsName));
            requestEngine.getDatabase().addAuthorization(authz); ids.add(dnsName);
        }
        var account = new ACMEAccount(); account.setID("account-1");
        var requestOrder = new ACMEOrder(); requestOrder.setID("order-csr"); requestOrder.setAuthzIDs(ids.toArray(String[]::new));
        var result = ACMECAAValidator.createRequest(requestEngine, account, requestOrder, readCSR("caa-names.csr"));
        assertEquals(Set.of("cn-only.example.com.", "www.example.com.", "api.example.com."),
                result.names().stream().map(n -> n.baseName().asciiAbsoluteName()).collect(java.util.stream.Collectors.toSet()));
        assertEquals(3, result.contexts().size());
    }

    @Test void eachNameGetsOnlyItsOwnSuccessfulValidationMethod() throws Exception {
        var requestEngine = requestEngine();
        var account = new ACMEAccount(); account.setID("account-1");
        var first = authorization();
        var second = authorization(); second.setID("authz-2");
        second.setIdentifier(new ACMEIdentifier("dns", "api.example.com"));
        second.getChallenges().iterator().next().setType("http-01");
        requestEngine.getDatabase().addAuthorization(first); requestEngine.getDatabase().addAuthorization(second);
        var requestOrder = new ACMEOrder(); requestOrder.setID("order-names"); requestOrder.setAuthzIDs(new String[] {"authz-1", "authz-2"});
        var result = ACMECAAValidator.createRequest(requestEngine, account, requestOrder, Set.of("WWW.EXAMPLE.COM", "api.example.com"));
        for (var name : result.names()) {
            assertEquals(name.baseName().equals(NAME) ? "dns-01" : "http-01",
                    result.contexts().get(name).validationMethod().orElseThrow());
        }
    }

    @Test void missingAuthorizationForOneSanPreventsBuildingTheRequest() throws Exception {
        var requestEngine = requestEngine(); requestEngine.getDatabase().addAuthorization(authorization());
        var account = new ACMEAccount(); account.setID("account-1");
        var requestOrder = new ACMEOrder(); requestOrder.setID("order"); requestOrder.setAuthzIDs(new String[] {"authz-1", "not-in-database"});
        assertThrows(IllegalArgumentException.class, () -> ACMECAAValidator.createRequest(requestEngine, account, requestOrder,
                Set.of("www.example.com", "api.example.com")));
    }

    @Test void pendingWrongNameAndNonDnsAuthorizationsCannotAuthorizeTheName() throws Exception {
        for (String state : List.of("pending", "wrong-name", "ip", "no-expiration")) {
            var requestEngine = requestEngine(); var authz = authorization();
            if (state.equals("pending")) authz.setStatus("pending");
            if (state.equals("wrong-name")) authz.setIdentifier(new ACMEIdentifier("dns", "other.example.com"));
            if (state.equals("ip")) authz.setIdentifier(new ACMEIdentifier("ip", "www.example.com"));
            if (state.equals("no-expiration")) authz.setExpirationTime(null);
            requestEngine.getDatabase().addAuthorization(authz);
            var account = new ACMEAccount(); account.setID("account-1");
            var requestOrder = new ACMEOrder(); requestOrder.setID("order"); requestOrder.setAuthzIDs(new String[] {"authz-1"});
            assertThrows(IllegalArgumentException.class,
                    () -> ACMECAAValidator.createRequest(requestEngine, account, requestOrder, Set.of("www.example.com")), state);
        }
    }

    @Test void invalidMissingTimeAndFutureChallengesCannotSupplyBindingMethod() throws Exception {
        for (String state : List.of("invalid", "no-time", "future", "no-challenges")) {
            var requestEngine = requestEngine(); var authz = authorization();
            var challenge = authz.getChallenges().iterator().next();
            if (state.equals("invalid")) challenge.setStatus("invalid");
            if (state.equals("no-time")) challenge.setValidationTime(null);
            if (state.equals("future")) challenge.setValidationTime(new Date(System.currentTimeMillis() + 60000));
            if (state.equals("no-challenges")) authz.setChallenges(null);
            requestEngine.getDatabase().addAuthorization(authz);
            var account = new ACMEAccount(); account.setID("account-1");
            var requestOrder = new ACMEOrder(); requestOrder.setID("order"); requestOrder.setAuthzIDs(new String[] {"authz-1"});
            var result = ACMECAAValidator.createRequest(requestEngine, account, requestOrder, Set.of("www.example.com"));
            assertTrue(result.contexts().get(result.names().get(0)).validationMethod().isEmpty(), state);
        }
    }

    @Test void duplicateSuccessfulAuthorizationsForTheSameMethodAreNotAmbiguous() throws Exception {
        var requestEngine = requestEngine(); var first = authorization(); var second = authorization(); second.setID("authz-2");
        requestEngine.getDatabase().addAuthorization(first); requestEngine.getDatabase().addAuthorization(second);
        var account = new ACMEAccount(); account.setID("account-1");
        var requestOrder = new ACMEOrder(); requestOrder.setID("order"); requestOrder.setAuthzIDs(new String[] {"authz-1", "authz-2"});
        var result = ACMECAAValidator.createRequest(requestEngine, account, requestOrder, Set.of("www.example.com"));
        assertEquals("dns-01", result.contexts().get(result.names().get(0)).validationMethod().orElseThrow());
    }

    /** Drives the servlet's explicit validation/issuance steps without the HTTP/JWS handler. */
    private String finalizeIssuance() throws Exception {
        engine.validateCSR(issuanceAccount, order, issuanceCSR);
        engine.validateCAA(issuanceAccount, order, issuanceCSR);
        return engine.getIssuer().issueCertificate(issuanceCSR);
    }

    /** Public CSR fixtures contain no private keys; signature verification is a separate stage. */
    private PKCS10 readCSR(String resource) throws Exception {
        String pem;
        try (var stream = getClass().getResourceAsStream(resource)) {
            assertNotNull(stream); pem = new String(stream.readAllBytes(), StandardCharsets.US_ASCII);
        }
        byte[] der = Base64.getMimeDecoder().decode(pem.replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                .replace("-----END CERTIFICATE REQUEST-----", ""));
        return new PKCS10(der, false);
    }

    private ACMEEngine requestEngine() throws Exception {
        ACMEEngine result = new ACMEEngine();
        Path file = directory.resolve("engine.conf");
        Files.writeString(file, "baseURL=https://acme.example/acme\n"); result.loadEngineConfig(file.toString());
        result.setDatabase(new InMemoryDatabase());
        return result;
    }

    private static ACMEAuthorization authorization() {
        ACMEAuthorization authz = new ACMEAuthorization();
        authz.setID("authz-1"); authz.setAccountID("account-1"); authz.setStatus("valid");
        authz.setIdentifier(new ACMEIdentifier("dns", "www.example.com")); authz.setExpirationTime(new Date(System.currentTimeMillis() + 60000));
        ACMEChallenge challenge = new ACMEChallenge(); challenge.setType("dns-01"); challenge.setStatus("valid"); challenge.setValidationTime(new Date(1));
        authz.setChallenges(List.of(challenge)); return authz;
    }

    private void configure(boolean enabled) throws Exception {
        Path path = directory.resolve("caa.conf");
        Files.writeString(path, "enabled=" + enabled + "\nissuerIdentifiers=ca.example\ndns.class=" + Provider.class.getName() + "\n");
        engine.initCAA(path.toString());
    }

    private static final class Engine extends ACMEEngine {
        boolean invalidCSR;
        boolean invalidContext;
        @Override public void validateCSR(ACMEAccount account, ACMEOrder order, PKCS10 csr) throws Exception {
            EVENTS.add("csr");
            if (invalidCSR) throw new Exception("invalid CSR fixture");
            if (invalidContext) getDatabase().getAuthorization("authz-1").setStatus("pending");
        }
        @Override public ACMEPolicy getPolicy() { return new ACMEPolicy(new ACMEPolicyConfig()); }
        @Override public void updateOrder(ACMEAccount account, ACMEOrder order) { EVENTS.add("persist-" + order.getStatus()); }
    }

    /** Configuration-loadable fixture belongs only in the test classpath. */
    public static final class Provider implements CAADNSClientProvider, CAADNSClient {
        static String value;
        static boolean fail;
        static int opens;
        static int closes;
        static DNSLookupException.Reason failureReason;
        @Override public ValidationMode validationMode() { return ValidationMode.UNCHECKED; }
        @Override public CAADNSClient open(Config config) { opens++; return this; }
        @Override public LookupResult resolveCaa(DNSDomainName name, LookupBudget budget) throws DNSLookupException {
            EVENTS.add("dns"); budget.reserveQuery();
            if (fail) throw new DNSLookupException(new DNSLookupException.Failure(failureReason,
                    "fixture failure", List.of()));
            return new LookupResult(name, name, LookupKind.RRSET,
                    List.of(new CAARecord(name, 60, 0, "issue", value.getBytes(StandardCharsets.US_ASCII))), List.of(),
                    List.of(new ResponseEvidence("fixture", name, 0, false, DNSSECStatus.UNCHECKED,
                            ValidationAssurance.NONE, Instant.now(), "fixture", Optional.empty())), Optional.empty());
        }
        @Override public void close() { closes++; }
    }
}
