// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later
package org.dogtagpki.acme.caa.libunbound;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.dogtagpki.acme.caa.CAADNSClient;
import org.dogtagpki.acme.caa.CAADNSClientProvider;
import org.dogtagpki.acme.caa.CAADecision;
import org.dogtagpki.acme.caa.CAAIssuanceGate;
import org.dogtagpki.acme.caa.CAAPolicy;
import org.dogtagpki.acme.caa.CAARequest;
import org.dogtagpki.acme.caa.DefaultCAAValidator;
import org.dogtagpki.acme.caa.DNSDomainName;
import org.dogtagpki.acme.caa.DNSLookupException;
import org.dogtagpki.acme.caa.TestCAALookupBudget;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

/** Real JNI calls and signed fixtures; dnsjava is used only to generate test packets. */
@Timeout(15)
class LibUnboundCAAProviderTest {
    @TempDir Path directory;
    private static KeyPair keys;
    private static DNSKEYRecord key;
    private static final Name ZONE = Name.fromConstantString("signed.caaunit.");
    private static final DNSDomainName NAME = new DNSDomainName("www.signed.caaunit.");
    @BeforeAll static void keys() throws Exception {
        keys = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        key = new DNSKEYRecord(ZONE, 1, 60, 257, 3, DNSSEC.Algorithm.RSASHA256, keys.getPublic());
    }

    @Test void preservesBinaryCaaAndDoesNotTrustForwarderAdInUncheckedMode() throws Exception {
        try (var server = new NativeDnsServer(query -> {
            var response = reply(query, 0);
            response.getHeader().setFlag(Flags.AD);
            response.addRecord(Record.newRecord(query.getQuestion().getName(), 257, 1, 73,
                    new byte[] {(byte)128, 6, 'f', 'u', 't', 'u', 'r', 'e', 0, (byte)255}), Section.ANSWER);
            return response.toWire();
        }); var dns = open(server, null)) {
            var result = dns.resolveCaa(NAME, budget());
            assertEquals(CAADNSClient.LookupKind.RRSET, result.kind());
            assertEquals(73, result.records().get(0).ttlSeconds());
            assertArrayEquals(new byte[] {0, (byte)255}, result.records().get(0).value());
            assertEquals(CAADNSClient.DNSSECStatus.UNCHECKED, result.responses().get(0).validationStatus());
        }
    }

    @Test void followsCnameAndDnameWithConnectedEvidence() throws Exception {
        for (boolean dname : List.of(false, true)) {
            try (var server = new NativeDnsServer(query -> {
                var response = reply(query, 0);
                if (query.getQuestion().getName().toString().equals(NAME.asciiAbsoluteName())) {
                    if (dname) response.addRecord(new DNAMERecord(ZONE, 1, 30, Name.fromConstantString("target.caaunit.")), Section.ANSWER);
                    response.addRecord(new CNAMERecord(query.getQuestion().getName(), 1, 30,
                            Name.fromConstantString("www.target.caaunit.")), Section.ANSWER);
                }
                response.addRecord(new CAARecord(Name.fromConstantString("www.target.caaunit."), 1, 60, 0, "issue", "ca.example"), Section.ANSWER);
                return response.toWire();
            }); var dns = open(server, null)) {
                var result = dns.resolveCaa(NAME, budget());
                assertEquals(new DNSDomainName("www.target.caaunit."), result.terminalName());
                assertEquals(dname ? CAADNSClient.AliasKind.DNAME_SYNTHESIS : CAADNSClient.AliasKind.CNAME, result.aliases().get(0).kind());
                assertEquals(30, result.aliases().get(0).ttlSeconds());
            }
        }
    }

    @Test void negativeResultsRetainSoaAndNameAbsence() throws Exception {
        for (int rcode : List.of(0, 3)) {
            try (var server = new NativeDnsServer(query -> {
                var response = reply(query, rcode);
                response.addRecord(soa(ZONE), Section.AUTHORITY);
                return response.toWire();
            }); var dns = open(server, null)) {
                var result = dns.resolveCaa(NAME, budget());
                assertEquals(rcode == 3 ? CAADNSClient.LookupKind.NXDOMAIN : CAADNSClient.LookupKind.NODATA, result.kind());
                assertEquals(30, result.negativeEvidence().orElseThrow().soa().orElseThrow().minimumSeconds());
            }
        }
    }

    @Test void authorizesThroughConfiguredGateAndNeverSubmitsDeniedCaa() throws Exception {
        AtomicInteger issued = new AtomicInteger();
        for (String issuer : List.of("ca.example", ";")) {
            try (var server = new NativeDnsServer(query -> {
                var response = reply(query, 0);
                response.addRecord(new CAARecord(query.getQuestion().getName(), 1, 60, 0, "issue", issuer), Section.ANSWER);
                return response.toWire();
            })) {
                var props = new Properties();
                props.setProperty("enabled", "true"); props.setProperty("issuerIdentifiers", "ca.example");
                props.setProperty("dns.class", LibUnboundCAAProvider.class.getName());
                props.setProperty("dns.settings.server", "127.0.0.1");
                props.setProperty("dns.settings.port", Integer.toString(server.address().getPort()));
                try (var gate = CAAIssuanceGate.open(props, getClass().getClassLoader())) {
                    var request = new CAARequest("order", List.of(new CAARequest.CertificateName(NAME, false)), Map.of());
                    if (issuer.equals(";")) assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                            () -> gate.issue(request, d -> {}, issued::incrementAndGet));
                    else assertEquals(1, gate.issue(request, d -> {}, issued::incrementAndGet));
                }
            }
        }
        assertEquals(1, issued.get());
    }

    @Test void secureDataIsAcceptedAndBogusDataBlocksIssuance() throws Exception {
        for (boolean signed : List.of(true, false)) {
            try (var server = new NativeDnsServer(query -> signedReply(query, signed)); var dns = open(server, anchor(key))) {
                if (signed) {
                    var result = dns.resolveCaa(NAME, budget());
                    assertEquals(CAADNSClient.DNSSECStatus.SECURE, result.responses().get(0).validationStatus());
                    assertEquals(CAADNSClient.ValidationAssurance.LOCAL_VALIDATOR, result.responses().get(0).assurance());
                } else assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE,
                        assertThrows(DNSLookupException.class, () -> dns.resolveCaa(NAME, budget())).failure().reason());
            }
        }
    }

    @Test void signedNegativeAnswerIsNotConfusedWithValidationFailure() throws Exception {
        try (var server = new NativeDnsServer(query -> {
            if (query.getQuestion().getType() == Type.DNSKEY) return signedReply(query, true);
            var response = reply(query, 0);
            addSigned(response, soa(ZONE), Section.AUTHORITY, key);
            addSigned(response, new NSECRecord(query.getQuestion().getName(), 1, 60,
                    Name.fromConstantString("zzz.signed.caaunit."), new int[] {Type.A, Type.NSEC, Type.RRSIG}), Section.AUTHORITY, key);
            return response.toWire();
        }); var dns = open(server, anchor(key))) {
            var result = dns.resolveCaa(NAME, budget());
            assertEquals(CAADNSClient.LookupKind.NODATA, result.kind());
            assertEquals(CAADNSClient.DNSSECStatus.SECURE, result.responses().get(0).validationStatus());
        }
    }

    @Test void rootAnchorAllowsAuthenticatedUnsignedDelegation() throws Exception {
        DNSKEYRecord root = new DNSKEYRecord(Name.root, 1, 60, 257, 3, DNSSEC.Algorithm.RSASHA256, keys.getPublic());
        try (var server = new NativeDnsServer(query -> {
            var response = reply(query, 0);
            if (query.getQuestion().getType() == Type.DNSKEY) addSigned(response, root, Section.ANSWER, root);
            else if (query.getQuestion().getType() == Type.DS) {
                addSigned(response, soa(Name.root), Section.AUTHORITY, root);
                addSigned(response, new NSECRecord(Name.fromConstantString("caaunit."), 1, 60,
                        Name.fromConstantString("zzz."), new int[] {Type.NS, Type.NSEC, Type.RRSIG}), Section.AUTHORITY, root);
            } else response.addRecord(new CAARecord(query.getQuestion().getName(), 1, 60, 0, "issue", "ca.example"), Section.ANSWER);
            return response.toWire();
        }); var dns = open(server, anchor(root))) {
            var result = dns.resolveCaa(new DNSDomainName("www.caaunit."), budget());
            assertEquals(CAADNSClient.DNSSECStatus.PROVEN_INSECURE, result.responses().get(0).validationStatus());
        }
    }

    @Test void badConfigurationAndMalformedAnchorFailAtOpen() throws Exception {
        assertThrows(DNSLookupException.class, () -> new LibUnboundCAAProvider.Validating().open(new CAADNSClientProvider.Config(Map.of("server", "127.0.0.1"))));
        Path file = directory.resolve("bad.key"); Files.writeString(file, ". IN DNSKEY 257 3 8 not-base64!!!\n");
        assertThrows(DNSLookupException.class, () -> new LibUnboundCAAProvider.Validating().open(new CAADNSClientProvider.Config(
                Map.of("server", "127.0.0.1", "trustAnchors", file.toString()))));
        assertThrows(DNSLookupException.class, () -> new LibUnboundCAAProvider().open(new CAADNSClientProvider.Config(Map.of("server", "dns.example"))));
    }

    @Test void managedAnchorStateCannotBeDiscardedAndPromotedToStaticTrust() throws Exception {
        Path file = directory.resolve("managed-root.key");
        Files.writeString(file, key + " ;;state=1 [ ADDPEND ]\n");
        assertThrows(DNSLookupException.class, () -> new LibUnboundCAAProvider.Validating().open(
                new CAADNSClientProvider.Config(Map.of("server", "127.0.0.1", "trustAnchors", file.toString()))));
    }

    @Test void unusableRootAnchorCannotTurnAllAnswersIntoAcceptableInsecurity() throws Exception {
        Path file = directory.resolve("unsupported-root.key");
        Files.writeString(file, ". IN DNSKEY 257 3 99 AQIDBA==\n");
        DNSKEYRecord root = new DNSKEYRecord(Name.root, 1, 60, 257, 3, DNSSEC.Algorithm.RSASHA256, keys.getPublic());
        try (var server = new NativeDnsServer(query -> {
            var response = reply(query, 0);
            if (query.getQuestion().getType() == Type.DNSKEY) addSigned(response, root, Section.ANSWER, root);
            else response.addRecord(new CAARecord(query.getQuestion().getName(), 1, 60, 0, "issue", "ca.example"), Section.ANSWER);
            return response.toWire();
        }); var dns = open(server, file)) {
            assertThrows(DNSLookupException.class, () -> dns.resolveCaa(new DNSDomainName("www.caaunit."), budget()));
        }
    }

    @Test void servfailAndTimeoutNeverAuthorize() throws Exception {
        for (boolean timeout : List.of(false, true)) {
            try (var server = new NativeDnsServer(query -> timeout ? null : reply(query, 2).toWire());
                    var dns = open(server, null); var validator = new DefaultCAAValidator(dns, new CAAPolicy(Set.of("ca.example")))) {
                var request = new CAARequest("order", List.of(new CAARequest.CertificateName(NAME, false)), Map.of());
                assertEquals(CAADecision.Outcome.ERROR, validator.validate(request).outcome());
            }
        }
    }

    @Test void closeCancelsNativeWaitAndRejectsNewCalls() throws Exception {
        CountDownLatch received = new CountDownLatch(1);
        try (var server = new NativeDnsServer(query -> { received.countDown(); return null; }); var dns = open(server, null)) {
            var workers = Executors.newSingleThreadExecutor();
            try {
                var pending = workers.submit(() -> assertThrows(DNSLookupException.class, () -> dns.resolveCaa(NAME, budget())));
                assertTrue(received.await(2, TimeUnit.SECONDS)); dns.close();
                assertEquals(DNSLookupException.Reason.CANCELLED, pending.get(2, TimeUnit.SECONDS).failure().reason());
                assertThrows(DNSLookupException.class, () -> dns.resolveCaa(NAME, budget()));
            } finally { workers.shutdownNow(); }
        }
    }

    @Test void evidenceReaderRejectsTruncationAndInconsistentRdata() throws Exception {
        Message response = reply(Message.newQuery(Record.newRecord(Name.fromConstantString(NAME.asciiAbsoluteName()), 257, 1)), 0);
        response.addRecord(new CAARecord(Name.fromConstantString(NAME.asciiAbsoluteName()), 1, 60, 0, "issue", "ca.example"), Section.ANSWER);
        byte[] wire = response.toWire();
        for (int length = 0; length < wire.length; length++) {
            byte[] truncated = java.util.Arrays.copyOf(wire, length);
            var result = new LibUnboundCAAProvider.NativeResult(null, 0, new byte[0][], 60, false, false, null, false, false, truncated);
            assertThrows(Exception.class, () -> UnboundCAAResponse.decode(NAME, result, "fixture", CAADNSClient.ValidationMode.UNCHECKED, budget(), Instant.now()));
        }
        var mismatch = new LibUnboundCAAProvider.NativeResult(null, 0, new byte[0][], 60, false, false, null, false, false, wire);
        assertThrows(Exception.class, () -> UnboundCAAResponse.decode(NAME, mismatch, "fixture", CAADNSClient.ValidationMode.UNCHECKED, budget(), Instant.now()));
    }

    @Test void signatureTimesOutsideTheValidatorsClockSkewCannotAuthorize() throws Exception {
        for (boolean expired : List.of(true, false)) {
            try (var server = new NativeDnsServer(query -> {
                if (query.getQuestion().getType() == Type.DNSKEY) return signedReply(query, true);
                var response = reply(query, 0);
                var record = new CAARecord(query.getQuestion().getName(), 1, 60, 0, "issue", "ca.example");
                response.addRecord(record, Section.ANSWER);
                try {
                    // Stay beyond libunbound's documented clock-skew allowance.
                    var start = Instant.now().plusSeconds(expired ? -8 * 86400 : 7 * 86400);
                    var end = Instant.now().plusSeconds(expired ? -7 * 86400 : 8 * 86400);
                    response.addRecord(DNSSEC.sign(new RRset(record), key, keys.getPrivate(), start, end), Section.ANSWER);
                } catch (Exception e) { throw new AssertionError(e); }
                return response.toWire();
            }); var dns = open(server, anchor(key))) {
                assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE,
                        assertThrows(DNSLookupException.class, () -> dns.resolveCaa(NAME, budget())).failure().reason());
            }
        }
    }

    @Test void modifiedSignedGrantCannotReachIssuerSubmission() throws Exception {
        var submitted = new AtomicInteger();
        try (var server = new NativeDnsServer(query -> {
            if (query.getQuestion().getType() == Type.DNSKEY) return signedReply(query, true);
            var response = reply(query, 0);
            var original = new CAARecord(query.getQuestion().getName(), 1, 60, 0, "issue", "other.example");
            addSigned(response, original, Section.ANSWER, key);
            response.removeRecord(original, Section.ANSWER);
            response.addRecord(new CAARecord(query.getQuestion().getName(), 1, 60, 0, "issue", "ca.example"), Section.ANSWER);
            return response.toWire();
        })) {
            var properties = new Properties();
            properties.setProperty("enabled", "true"); properties.setProperty("issuerIdentifiers", "ca.example");
            properties.setProperty("dns.class", LibUnboundCAAProvider.Validating.class.getName());
            properties.setProperty("dns.settings.server", "127.0.0.1");
            properties.setProperty("dns.settings.port", Integer.toString(server.address().getPort()));
            properties.setProperty("dns.settings.trustAnchors", anchor(key).toString());
            try (var gate = CAAIssuanceGate.open(properties, getClass().getClassLoader())) {
                var request = new CAARequest("order", List.of(new CAARequest.CertificateName(NAME, false)), Map.of());
                var error = assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                        () -> gate.issue(request, d -> {}, submitted::incrementAndGet));
                assertEquals(CAADecision.Outcome.ERROR, error.decision().outcome());
                assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE,
                        error.decision().names().get(0).failure().orElseThrow().reason());
                assertEquals(0, submitted.get());
            }
        }
    }

    @Test void aForwardersAdBitDoesNotReplaceLocalSignatureValidation() throws Exception {
        try (var server = new NativeDnsServer(query -> {
            var response = reply(query, 0);
            if (query.getQuestion().getType() == Type.DNSKEY) addSigned(response, key, Section.ANSWER, key);
            else response.addRecord(new CAARecord(query.getQuestion().getName(), 1, 60, 0, "issue", "ca.example"), Section.ANSWER);
            response.getHeader().setFlag(Flags.AD);
            return response.toWire();
        }); var dns = open(server, anchor(key))) {
            assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE,
                    assertThrows(DNSLookupException.class, () -> dns.resolveCaa(NAME, budget())).failure().reason());
        }
    }

    @Test void anchorChangesRequireReopeningAndCannotAlterAnActiveSnapshot() throws Exception {
        Path file = anchor(key);
        try (var server = new NativeDnsServer(query -> signedReply(query, true)); var dns = open(server, file)) {
            Files.writeString(file, "not an anchor\n");
            assertEquals(CAADNSClient.DNSSECStatus.SECURE, dns.resolveCaa(NAME, budget()).responses().get(0).validationStatus());
            assertEquals(DNSLookupException.Reason.CONFIGURATION,
                    assertThrows(DNSLookupException.class, () -> open(server, file)).failure().reason());
        }
    }

    @Test void wrongButWellFormedTrustedKeyCannotValidateTheZone() throws Exception {
        var other = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        var wrong = new DNSKEYRecord(ZONE, 1, 60, 257, 3, DNSSEC.Algorithm.RSASHA256, other.getPublic());
        try (var server = new NativeDnsServer(query -> signedReply(query, true)); var dns = open(server, anchor(wrong))) {
            assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE,
                    assertThrows(DNSLookupException.class, () -> dns.resolveCaa(NAME, budget())).failure().reason());
        }
    }

    @Test void anchorAndEndpointFailuresNeverSelectUncheckedFallback() throws Exception {
        for (String contents : List.of("", ". IN DS 1 13 2 not-hex\n", ";;state=1\n" + key,
                ". IN DNSKEY 257 3 13 ( AQID )\n", "\u00e9 IN DS 1 13 2 01234567\n")) {
            Path file = directory.resolve("invalid-anchors.key"); Files.writeString(file, contents);
            var config = new CAADNSClientProvider.Config(Map.of("server", "127.0.0.1", "trustAnchors", file.toString()));
            assertEquals(DNSLookupException.Reason.CONFIGURATION,
                    assertThrows(DNSLookupException.class, () -> new LibUnboundCAAProvider.Validating().open(config)).failure().reason());
        }
        for (String port : List.of("0", "65536", "-1", "not-a-port")) {
            var config = new CAADNSClientProvider.Config(Map.of("server", "127.0.0.1", "port", port));
            assertEquals(DNSLookupException.Reason.CONFIGURATION,
                    assertThrows(DNSLookupException.class, () -> new LibUnboundCAAProvider().open(config)).failure().reason());
        }
        var config = new CAADNSClientProvider.Config(Map.of("server", "127.0.0.1", "trustAnchors", anchor(key).toString()));
        assertThrows(DNSLookupException.class, () -> new LibUnboundCAAProvider().open(config));
    }

    @Test void concurrentCallsKeepTheirNativeResultsAndPacketEvidenceSeparate() throws Exception {
        var workers = Executors.newFixedThreadPool(4);
        try (var server = new NativeDnsServer(query -> {
            var response = reply(query, 0);
            response.addRecord(new CAARecord(query.getQuestion().getName(), 1, 60, 0, "issue", "ca.example"), Section.ANSWER);
            return response.toWire();
        }); var dns = open(server, null)) {
            var pending = new java.util.ArrayList<java.util.concurrent.Future<CAADNSClient.LookupResult>>();
            for (int i = 0; i < 4; i++) {
                var candidate = new DNSDomainName("n" + i + ".signed.caaunit.");
                pending.add(workers.submit(() -> dns.resolveCaa(candidate, budget())));
            }
            for (int i = 0; i < pending.size(); i++) {
                var expected = new DNSDomainName("n" + i + ".signed.caaunit.");
                var result = pending.get(i).get(3, TimeUnit.SECONDS);
                assertEquals(expected, result.candidate());
                assertEquals(expected, result.records().get(0).owner());
                assertEquals(expected, result.responses().get(0).question());
            }
        } finally { workers.shutdownNow(); }
    }

    private CAADNSClient open(NativeDnsServer server, Path anchors) throws Exception {
        var config = new java.util.HashMap<String, String>();
        config.put("server", "127.0.0.1"); config.put("port", Integer.toString(server.address().getPort()));
        if (anchors != null) config.put("trustAnchors", anchors.toString());
        return (anchors == null ? new LibUnboundCAAProvider() : new LibUnboundCAAProvider.Validating()).open(new CAADNSClientProvider.Config(config));
    }
    private Path anchor(DNSKEYRecord record) throws Exception {
        Path path = directory.resolve("root.key"); Files.writeString(path, record + "\n"); return path;
    }
    private static TestCAALookupBudget budget() { return new TestCAALookupBudget(new CAAPolicy(Set.of("ca.example")).limits()); }
    private static SOARecord soa(Name zone) {
        return new SOARecord(zone, 1, 120, Name.fromConstantString("ns.caaunit."), Name.fromConstantString("hostmaster.caaunit."), 1, 60, 60, 60, 30);
    }
    private static Message reply(Message query, int code) {
        Message response = new Message(query.getHeader().getID());
        response.getHeader().setFlag(Flags.QR); response.getHeader().setFlag(Flags.RD); response.getHeader().setFlag(Flags.RA);
        response.getHeader().setRcode(code); response.addRecord(query.getQuestion(), Section.QUESTION); return response;
    }
    private static byte[] signedReply(Message query, boolean signed) {
        var response = reply(query, 0);
        if (query.getQuestion().getType() == Type.DNSKEY) addSigned(response, key, Section.ANSWER, key);
        else {
            var record = new CAARecord(query.getQuestion().getName(), 1, 60, 0, "issue", "ca.example");
            if (signed) addSigned(response, record, Section.ANSWER, key); else response.addRecord(record, Section.ANSWER);
        }
        return response.toWire();
    }
    private static void addSigned(Message response, Record record, int section, DNSKEYRecord signingKey) {
        try {
            response.addRecord(record, section);
            response.addRecord(DNSSEC.sign(new RRset(record), signingKey, keys.getPrivate(),
                    Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600)), section);
        } catch (Exception e) { throw new AssertionError(e); }
    }
}
