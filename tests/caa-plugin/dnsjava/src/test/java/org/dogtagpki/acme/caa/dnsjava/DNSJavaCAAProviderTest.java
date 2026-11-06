// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa.dnsjava;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import org.dogtagpki.acme.caa.CAADNSClient;
import org.dogtagpki.acme.caa.CAADNSClientProvider;
import org.dogtagpki.acme.caa.CAAPolicy;
import org.dogtagpki.acme.caa.CAARequest;
import org.dogtagpki.acme.caa.DNSDomainName;
import org.dogtagpki.acme.caa.DNSLookupException;
import org.dogtagpki.acme.caa.TestCAALookupBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.xbill.DNS.CAARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNAMERecord;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.ExtendedFlags;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.OPTRecord;
import org.xbill.DNS.Opcode;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

/** Contract tests use real TCP packets and deterministic local DNS data. */
@Timeout(10)
public class DNSJavaCAAProviderTest {

    private static final DNSDomainName NAME = new DNSDomainName("www.customer.test.");
    private static final String ROOT_ANCHOR = ". IN DS 12345 13 2 " + "00".repeat(32) + "\n";
    @TempDir Path temporary;

    @Test
    void inProcessValidationRequiresAnExplicitAnchorFile() {
        assertEquals(CAADNSClient.ValidationMode.LOCAL_ENFORCING,
                new DNSJavaCAAProvider.Validating().validationMode());
        assertReason(DNSLookupException.Reason.CONFIGURATION, () -> new DNSJavaCAAProvider.Validating()
                .open(new CAADNSClientProvider.Config(Map.of("server", "127.0.0.1"))));
    }

    @Test
    void trustAnchorsAreRejectedByUncheckedAndDelegatedProviders() throws Exception {
        Path anchors = temporary.resolve("anchors");
        Files.writeString(anchors, ROOT_ANCHOR);
        var config = new CAADNSClientProvider.Config(Map.of("server", "127.0.0.1",
                "trustAnchors", anchors.toString()));
        assertReason(DNSLookupException.Reason.CONFIGURATION, () -> new DNSJavaCAAProvider().open(config));
        assertReason(DNSLookupException.Reason.CONFIGURATION,
                () -> new DNSJavaCAAProvider.LocalValidatingResolver().open(config));
    }

    @Test
    void rejectsMalformedOrManagedAnchorFiles() throws Exception {
        Path anchors = temporary.resolve("anchors");
        var config = new CAADNSClientProvider.Config(Map.of("server", "127.0.0.1",
                "trustAnchors", anchors.toString()));
        for (String value : List.of("", "; comment only\n", "\u00e9", ". IN TXT value\n",
                "$INCLUDE other-file\n", ". IN DS 12345 13 2 NOTHEX\n",
                ";;state=2 [ VALID ]\n" + ROOT_ANCHOR, "; autotrust trust anchor file\n" + ROOT_ANCHOR,
                ". IN DNSKEY 385 3 13 " + "AA".repeat(40) + "\n")) {
            Files.writeString(anchors, value);
            assertReason(DNSLookupException.Reason.CONFIGURATION,
                    () -> new DNSJavaCAAProvider.Validating().open(config));
        }
        Files.delete(anchors);
        assertReason(DNSLookupException.Reason.CONFIGURATION,
                () -> new DNSJavaCAAProvider.Validating().open(config));
    }

    @Test
    void rejectsOversizedAnchorFiles() throws Exception {
        Path anchors = temporary.resolve("anchors");
        Files.writeString(anchors, " ".repeat(1024 * 1024 + 1));
        assertReason(DNSLookupException.Reason.CONFIGURATION,
                () -> new DNSJavaCAAProvider.Validating().open(new CAADNSClientProvider.Config(
                        Map.of("server", "127.0.0.1", "trustAnchors", anchors.toString()))));
    }

    @Test
    void upstreamAdCannotReplaceLocalRootValidation() throws Exception {
        try (Fixture dns = new Fixture(query -> {
            Message response = reply(query, Rcode.NOERROR,
                    new DNSKEYRecord(name("."), DClass.IN, 60, 257, 3, 13, new byte[64]));
            response.getHeader().setFlag(Flags.AD);
            return response;
        }); var client = openLocal(dns)) {
            assertReason(DNSLookupException.Reason.VALIDATION_FAILURE,
                    () -> client.resolveCaa(NAME, budget()));
            assertTrue(dns.names().stream().allMatch("."::equals));
        }
    }

    @Test
    void localAnchorsAreSnapshottedUntilRestart() throws Exception {
        try (Fixture dns = new Fixture(query -> reply(query, Rcode.NOERROR)); var client = openLocal(dns)) {
            Files.delete(temporary.resolve("anchors"));
            assertReason(DNSLookupException.Reason.VALIDATION_FAILURE,
                    () -> client.resolveCaa(NAME, budget()));
        }
    }

    @Test
    void localValidationHonorsTheLookupDeadline() throws Exception {
        try (Fixture dns = new Fixture(query -> null); var client = openLocal(dns)) {
            var limited = new TestCAALookupBudget(new CAAPolicy.Limits(
                    Duration.ofMillis(150), Duration.ofMillis(150), 10, 10, 1));
            assertReason(DNSLookupException.Reason.TIMEOUT, () -> client.resolveCaa(NAME, limited));
        }
    }

    @Test
    void closingLocalValidationCancelsSupportingQueries() throws Exception {
        var arrived = new CountDownLatch(1);
        var workers = Executors.newSingleThreadExecutor();
        try (Fixture dns = new Fixture(query -> { arrived.countDown(); return null; });
                var client = openLocal(dns)) {
            Future<DNSLookupException.Reason> result = workers.submit(() -> {
                try {
                    client.resolveCaa(NAME, budget());
                    throw new AssertionError("Expected cancellation");
                } catch (DNSLookupException error) { return error.failure().reason(); }
            });
            assertTrue(arrived.await(2, TimeUnit.SECONDS));
            client.close();
            assertEquals(DNSLookupException.Reason.CANCELLED, result.get(2, TimeUnit.SECONDS));
        } finally { workers.shutdownNow(); }
    }

    @Test
    void rootPrimingConsumesTheSupportingQueryBudget() throws Exception {
        try (Fixture dns = new Fixture(query -> reply(query, Rcode.NOERROR,
                new DNSKEYRecord(name("."), DClass.IN, 60, 257, 3, 13, new byte[64])));
                var client = openLocal(dns)) {
            var limited = new TestCAALookupBudget(new CAAPolicy.Limits(
                    Duration.ofSeconds(2), Duration.ofSeconds(1), 1, 10, 1));
            assertReason(DNSLookupException.Reason.LIMIT_EXCEEDED, () -> client.resolveCaa(NAME, limited));
        }
    }

    private CAADNSClient openLocal(Fixture dns) throws Exception {
        Path anchors = temporary.resolve("anchors");
        Files.writeString(anchors, ROOT_ANCHOR);
        var settings = new java.util.HashMap<>(dns.config().settings());
        settings.put("trustAnchors", anchors.toString());
        return new DNSJavaCAAProvider.Validating().open(new CAADNSClientProvider.Config(settings));
    }

    @Test
    void zoneOnlyAnchorsCannotAuthorizeAnUncoveredUnsignedAnswer() throws Exception {
        Path anchors = temporary.resolve("zone-only");
        Files.writeString(anchors, ROOT_ANCHOR.replace(". IN DS", "other.test. IN DS"));
        try (Fixture dns = new Fixture(query -> {
            Message response = reply(query, Rcode.NOERROR, caa(NAME.asciiAbsoluteName(), new byte[] {'x'}));
            response.getHeader().setFlag(Flags.AD);
            return response;
        })) {
            var settings = new java.util.HashMap<>(dns.config().settings());
            settings.put("trustAnchors", anchors.toString());
            try (var client = new DNSJavaCAAProvider.Validating().open(new CAADNSClientProvider.Config(settings))) {
                assertReason(DNSLookupException.Reason.VALIDATION_FAILURE,
                        () -> client.resolveCaa(NAME, budget()));
            }
        }
    }

    @Test
    void preservesConfigurationCauseWithoutExposingSettingsInFailureMessage() {
        var config = new CAADNSClientProvider.Config(Map.of("server", "127.0.0.1", "port", "private value"));
        DNSLookupException error = assertThrows(DNSLookupException.class, () -> new DNSJavaCAAProvider().open(config));
        assertEquals(DNSLookupException.Reason.CONFIGURATION, error.failure().reason());
        assertTrue(error.getCause() instanceof NumberFormatException);
        assertFalse(error.getMessage().contains("private value"));
    }

    @Test
    void preservesBinaryCaaAndDoesNotTreatRawAdAsUncheckedAssurance() throws Exception {
        try (Fixture dns = new Fixture(q -> {
            Message r = reply(q, Rcode.NOERROR, caa(NAME.asciiAbsoluteName(), new byte[] { 0, (byte) 255 }));
            r.getHeader().setFlag(Flags.AD);
            return r;
        }); CAADNSClient client = open(dns, false)) {
            var answer = client.resolveCaa(NAME, budget());
            assertEquals(CAADNSClient.LookupKind.RRSET, answer.kind());
            assertEquals(NAME, answer.records().get(0).owner());
            assertEquals(60, answer.records().get(0).ttlSeconds());
            assertArrayEquals(new byte[] { 0, (byte) 255 }, answer.records().get(0).value());
            assertTrue(answer.responses().get(0).authenticatedData());
            assertEquals(CAADNSClient.DNSSECStatus.UNCHECKED, answer.responses().get(0).validationStatus());
            assertEquals(CAADNSClient.ValidationAssurance.NONE, answer.responses().get(0).assurance());
        }
    }

    @Test
    void followsAliasOnlyRepliesWithoutClimbingEitherParent() throws Exception {
        try (Fixture dns = new Fixture(q -> q.getQuestion().getName().toString().equals(NAME.asciiAbsoluteName())
                ? reply(q, 0, cname(NAME.asciiAbsoluteName(), "edge.provider.test."))
                : reply(q, 0, caa("edge.provider.test.", new byte[] { 'x' })));
                CAADNSClient client = open(dns, false)) {
            var answer = client.resolveCaa(NAME, budget());
            assertEquals(new DNSDomainName("edge.provider.test."), answer.terminalName());
            assertEquals(1, answer.aliases().size());
            assertEquals(2, answer.responses().size());
            assertEquals(List.of(NAME.asciiAbsoluteName(), "edge.provider.test."), dns.names());
        }
    }

    @Test
    void acceptsCompleteCnameAndDnameChainsInOneReply() throws Exception {
        for (boolean includeDname : List.of(false, true)) {
            try (Fixture dns = new Fixture(q -> {
                List<Record> records = new ArrayList<>();
                if (includeDname) {
                    records.add(new DNAMERecord(name("customer.test."), DClass.IN, 45, name("provider.test.")));
                }
                records.add(cname(NAME.asciiAbsoluteName(), "www.provider.test."));
                records.add(caa("www.provider.test.", new byte[] { 'x' }));
                return reply(q, 0, records.toArray(Record[]::new));
            }); CAADNSClient client = open(dns, false)) {
                var answer = client.resolveCaa(NAME, budget());
                assertEquals(CAADNSClient.LookupKind.RRSET, answer.kind());
                assertEquals(includeDname ? CAADNSClient.AliasKind.DNAME_SYNTHESIS : CAADNSClient.AliasKind.CNAME,
                        answer.aliases().get(0).kind());
                assertEquals(1, dns.names().size());
            }
        }
    }

    @Test
    void synthesizesDnameWhenTheReplyOmitsItsCname() throws Exception {
        try (Fixture dns = new Fixture(q -> reply(q, 0,
                new DNAMERecord(name("customer.test."), DClass.IN, 45, name("provider.test.")),
                caa("www.provider.test.", new byte[] { 'x' }))); CAADNSClient client = open(dns, false)) {
            var result = client.resolveCaa(NAME, budget());
            assertEquals(new DNSDomainName("www.provider.test."), result.terminalName());
            assertEquals(45, result.aliases().get(0).ttlSeconds());
        }
    }

    @Test
    void rejectsInvalidDnameSynthesisAndAliasLoops() throws Exception {
        try (Fixture dns = new Fixture(q -> reply(q, 0,
                new DNAMERecord(name("customer.test."), DClass.IN, 45, name("provider.test.")),
                cname(NAME.asciiAbsoluteName(), "wrong.test."))); CAADNSClient client = open(dns, false)) {
            assertReason(DNSLookupException.Reason.MALFORMED_RESPONSE, () -> client.resolveCaa(NAME, budget()));
        }
        try (Fixture dns = new Fixture(q -> reply(q, 0, cname(q.getQuestion().getName().toString(),
                q.getQuestion().getName().toString().equals(NAME.asciiAbsoluteName()) ? "edge.test." : NAME.asciiAbsoluteName())));
                CAADNSClient client = open(dns, false)) {
            assertReason(DNSLookupException.Reason.ALIAS_LOOP, () -> client.resolveCaa(NAME, budget()));
        }
    }

    @Test
    void preservesNodataSoaAndAcceptsExplicitEmptyRecursiveAnswers() throws Exception {
        for (boolean includeSoa : List.of(false, true)) {
            try (Fixture dns = new Fixture(q -> {
                Message r = reply(q, 0);
                if (includeSoa) r.addRecord(soa("customer.test."), Section.AUTHORITY);
                return r;
            }); CAADNSClient client = open(dns, false)) {
                var result = client.resolveCaa(NAME, budget());
                assertEquals(CAADNSClient.LookupKind.NODATA, result.kind());
                assertEquals(includeSoa, result.negativeEvidence().orElseThrow().soa().isPresent());
                if (includeSoa) {
                    var soa = result.negativeEvidence().orElseThrow().soa().orElseThrow();
                    assertEquals(30, soa.ttlSeconds());
                    assertEquals(15, soa.minimumSeconds());
                }
            }
        }
    }

    @Test
    void identifiesNxdomainAtTheAliasTargetWithoutRequerying() throws Exception {
        try (Fixture dns = new Fixture(q -> reply(q, Rcode.NXDOMAIN,
                cname(NAME.asciiAbsoluteName(), "missing.provider.test."))); CAADNSClient client = open(dns, false)) {
            var result = client.resolveCaa(NAME, budget());
            assertEquals(CAADNSClient.LookupKind.NXDOMAIN, result.kind());
            assertEquals(new DNSDomainName("missing.provider.test."), result.negativeEvidence().orElseThrow().terminalName());
            assertEquals(1, dns.names().size());
        }
    }

    @Test
    void rejectsReferralsUnrelatedAnswersAndMismatchedNegativeOwners() throws Exception {
        for (int variant = 0; variant < 3; variant++) {
            int v = variant;
            try (Fixture dns = new Fixture(q -> {
                Message r = reply(q, 0);
                if (v == 0) r.addRecord(new NSRecord(name("customer.test."), DClass.IN, 30, name("ns.test.")), Section.AUTHORITY);
                if (v == 1) r.addRecord(caa("unrelated.test.", new byte[] { 'x' }), Section.ANSWER);
                if (v == 2) r.addRecord(soa("unrelated.test."), Section.AUTHORITY);
                return r;
            }); CAADNSClient client = open(dns, false)) {
                assertReason(DNSLookupException.Reason.INCOMPLETE_ANSWER, () -> client.resolveCaa(NAME, budget()));
            }
        }
    }

    @Test
    void preservesServfailAsFailureAndRejectsTruncatedTcp() throws Exception {
        try (Fixture dns = new Fixture(q -> reply(q, Rcode.SERVFAIL)); CAADNSClient client = open(dns, false)) {
            DNSLookupException e = assertThrows(DNSLookupException.class, () -> client.resolveCaa(NAME, budget()));
            assertEquals(DNSLookupException.Reason.RCODE_FAILURE, e.failure().reason());
            assertEquals(Rcode.SERVFAIL, e.failure().partialResponses().get(0).rcode());
        }
        try (Fixture dns = new Fixture(q -> {
            Message r = reply(q, 0);
            r.getHeader().setFlag(Flags.TC);
            return r;
        }); CAADNSClient client = open(dns, false)) {
            assertReason(DNSLookupException.Reason.INCOMPLETE_ANSWER, () -> client.resolveCaa(NAME, budget()));
        }
    }

    @Test
    void validatesDelegatedFlagsAndRetainsMixedAdEvidence() throws Exception {
        try (Fixture dns = new Fixture(q -> {
            assertTrue(q.getHeader().getFlag(Flags.RD));
            assertTrue(q.getHeader().getFlag(Flags.AD));
            assertFalse(q.getHeader().getFlag(Flags.CD));
            assertTrue((q.getOPT().getFlags() & ExtendedFlags.DO) != 0);
            boolean first = q.getQuestion().getName().toString().equals(NAME.asciiAbsoluteName());
            Message r = first ? reply(q, 0, cname(NAME.asciiAbsoluteName(), "edge.test."))
                    : reply(q, 0, caa("edge.test.", new byte[] { 'x' }));
            if (!first) r.getHeader().setFlag(Flags.AD);
            return r;
        }); CAADNSClient client = open(dns, true)) {
            var result = client.resolveCaa(NAME, budget());
            assertEquals(CAADNSClient.DNSSECStatus.UNCLASSIFIED, result.responses().get(0).validationStatus());
            assertEquals(CAADNSClient.DNSSECStatus.SECURE, result.responses().get(1).validationStatus());
            assertTrue(result.responses().stream().allMatch(r -> r.assurance() == CAADNSClient.ValidationAssurance.TRUSTED_RESOLVER));
        }
    }

    @Test
    void delegatedDnssecErrorIsTypedWithoutGuessingFromServfailOrAdClear() throws Exception {
        for (int code : List.of(5, 6, 7, 8, 9, 10, 11, 12, 22)) {
            try (Fixture dns = new Fixture(q -> {
                Message response = reply(q, Rcode.SERVFAIL);
                OPTRecord opt = new OPTRecord(1232, 0, 0, 0,
                        new ExtendedErrorCodeOption(code, "fixture diagnostic"));
                response.addRecord(opt, Section.ADDITIONAL);
                return response;
            }); CAADNSClient client = open(dns, true)) {
                var failure = assertThrows(DNSLookupException.class, () -> client.resolveCaa(NAME, budget())).failure();
                assertEquals(code == 22 ? DNSLookupException.Reason.RCODE_FAILURE
                        : DNSLookupException.Reason.VALIDATION_FAILURE, failure.reason());
                assertEquals(code, failure.partialResponses().get(0).diagnostic().orElseThrow().code());
            }
        }
        try (Fixture dns = new Fixture(q -> reply(q, Rcode.SERVFAIL)); CAADNSClient client = open(dns, true)) {
            assertReason(DNSLookupException.Reason.RCODE_FAILURE, () -> client.resolveCaa(NAME, budget()));
        }
    }

    @Test
    void rejectsBehaviorKnobsAndInvalidEndpoints() {
        var unchecked = new DNSJavaCAAProvider();
        for (Map<String, String> settings : List.of(
                Map.of("server", "127.0.0.1", "validationMode", "DELEGATED_ENFORCING"),
                Map.of("server", "127.0.0.1", "trustValidatingResolver", "true"),
                Map.of("server", "127.0.0.1", "version", "1"),
                Map.of("server", "resolver.test"),
                Map.of("server", "127.0.0.1", "unknown", "true"))) {
            assertReason(DNSLookupException.Reason.CONFIGURATION,
                    () -> unchecked.open(new CAADNSClientProvider.Config(settings)));
        }
        assertReason(DNSLookupException.Reason.CONFIGURATION,
                () -> new DNSJavaCAAProvider.LocalValidatingResolver().open(
                        new CAADNSClientProvider.Config(Map.of("server", "8.8.8.8"))));
        assertEquals(CAADNSClient.ValidationMode.UNCHECKED, unchecked.validationMode());
        assertEquals(CAADNSClient.ValidationMode.DELEGATED_ENFORCING,
                new DNSJavaCAAProvider.LocalValidatingResolver().validationMode());
    }

    @Test
    void rejectsConflictingAliasesAndCaaAlongsideAnAlias() throws Exception {
        for (boolean withCaa : List.of(false, true)) {
            try (Fixture dns = new Fixture(q -> reply(q, 0,
                    cname(NAME.asciiAbsoluteName(), "one.test."), withCaa
                        ? caa(NAME.asciiAbsoluteName(), new byte[] { 'x' })
                        : cname(NAME.asciiAbsoluteName(), "two.test.")));
                    CAADNSClient client = open(dns, false)) {
                assertReason(DNSLookupException.Reason.MALFORMED_RESPONSE, () -> client.resolveCaa(NAME, budget()));
            }
        }
    }

    @Test
    void rejectsMismatchedQuestionsAndNonrecursiveOrCdResponses() throws Exception {
        for (int variant = 0; variant < 3; variant++) {
            int v = variant;
            try (Fixture dns = new Fixture(q -> {
                Message r = reply(q, 0);
                if (v == 0) {
                    r.removeAllRecords(Section.QUESTION);
                    r.addRecord(Record.newRecord(name("wrong.test."), Type.CAA, DClass.IN), Section.QUESTION);
                }
                if (v == 1) r.getHeader().unsetFlag(Flags.RA);
                if (v == 2) r.getHeader().setFlag(Flags.CD);
                return r;
            }); CAADNSClient client = open(dns, false)) {
                assertReason(v == 0 ? DNSLookupException.Reason.MALFORMED_RESPONSE
                        : DNSLookupException.Reason.INCOMPLETE_ANSWER, () -> client.resolveCaa(NAME, budget()));
            }
        }
    }

    @Test
    void refusesOversizedRecordSections() throws Exception {
        try (Fixture dns = new Fixture(q -> {
            Message r = reply(q, 0);
            for (int i = 0; i < 1025; i++) {
                r.addRecord(caa("r" + i + ".test.", new byte[] { 'x' }), Section.ADDITIONAL);
            }
            return r;
        }); CAADNSClient client = open(dns, false)) {
            assertReason(DNSLookupException.Reason.LIMIT_EXCEEDED, () -> client.resolveCaa(NAME, budget()));
        }
    }

    @Test
    void sharesBudgetsAcrossAliasQueriesAndRetainsPartialEvidence() throws Exception {
        try (Fixture dns = new Fixture(q -> reply(q, 0, cname(NAME.asciiAbsoluteName(), "edge.test.")));
                CAADNSClient client = open(dns, false)) {
            var limited = new TestCAALookupBudget(new CAAPolicy.Limits(Duration.ofSeconds(2), Duration.ofSeconds(1), 1, 3, 1));
            DNSLookupException e = assertThrows(DNSLookupException.class, () -> client.resolveCaa(NAME, limited));
            assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED, e.failure().reason());
            assertEquals(1, e.failure().partialResponses().size());
            assertEquals(1, dns.names().size());
        }
    }

    @Test
    void timesOutAndRejectsCallsAfterClose() throws Exception {
        try (Fixture dns = new Fixture(q -> null); CAADNSClient client = open(dns, false)) {
            var limited = new TestCAALookupBudget(new CAAPolicy.Limits(Duration.ofMillis(300), Duration.ofMillis(150), 2, 2, 1));
            assertReason(DNSLookupException.Reason.TIMEOUT, () -> client.resolveCaa(NAME, limited));
            client.close();
            assertReason(DNSLookupException.Reason.CANCELLED, () -> client.resolveCaa(NAME, budget()));
        }
    }

    @Test
    void cancelsAnActiveQueryOnClose() throws Exception {
        CountDownLatch received = new CountDownLatch(1);
        try (Fixture dns = new Fixture(q -> {
            received.countDown();
            return null;
        }); CAADNSClient client = open(dns, false)) {
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                var result = worker.submit(() -> assertThrows(DNSLookupException.class, () -> client.resolveCaa(NAME, budget())));
                assertTrue(received.await(2, TimeUnit.SECONDS));
                client.close();
                assertEquals(DNSLookupException.Reason.CANCELLED, result.get(2, TimeUnit.SECONDS).failure().reason());
            } finally {
                worker.shutdownNow();
            }
        }
    }

    @Test
    void loadsTheOptionalAdapterByClassNameWithoutDnsjavaTypesInTheEngine() throws Exception {
        var submitted = new java.util.concurrent.atomic.AtomicInteger();
        for (String issuer : List.of("issuer.test", ";")) {
            try (Fixture dns = new Fixture(q -> reply(q, 0,
                    caa(NAME.asciiAbsoluteName(), issuer.getBytes(java.nio.charset.StandardCharsets.US_ASCII))))) {
                var properties = new java.util.Properties();
                properties.setProperty("enabled", "true");
                properties.setProperty("issuerIdentifiers", "issuer.test");
                properties.setProperty("dns.class", DNSJavaCAAProvider.class.getName());
                dns.config().settings().forEach((key, value) -> properties.setProperty("dns.settings." + key, value));
                try (var gate = org.dogtagpki.acme.caa.CAAIssuanceGate.open(properties, getClass().getClassLoader())) {
                    var request = new CAARequest("acme-caller", List.of(new CAARequest.CertificateName(NAME, false)), Map.of());
                    if (issuer.equals(";")) {
                        assertThrows(org.dogtagpki.acme.caa.CAAIssuanceGate.CAAApprovalException.class,
                                () -> gate.issue(request, d -> {}, submitted::incrementAndGet));
                    } else {
                        assertEquals(1, gate.issue(request,
                                d -> assertEquals(1, d.names().get(0).discovery().size()), submitted::incrementAndGet));
                    }
                }
            }
        }
        assertEquals(1, submitted.get());
    }

    @Test
    void delegatedNegativeAnswersRetainSecureOrUnclassifiedAssurance() throws Exception {
        for (boolean ad : List.of(false, true)) {
            for (int rcode : List.of(Rcode.NOERROR, Rcode.NXDOMAIN)) {
                try (Fixture dns = new Fixture(q -> {
                    var response = reply(q, rcode);
                    response.addRecord(soa("customer.test."), Section.AUTHORITY);
                    if (ad) response.getHeader().setFlag(Flags.AD);
                    return response;
                }); var client = open(dns, true)) {
                    var result = client.resolveCaa(NAME, budget());
                    assertEquals(rcode == Rcode.NXDOMAIN ? CAADNSClient.LookupKind.NXDOMAIN : CAADNSClient.LookupKind.NODATA, result.kind());
                    assertEquals(ad ? CAADNSClient.DNSSECStatus.SECURE : CAADNSClient.DNSSECStatus.UNCLASSIFIED,
                            result.responses().get(0).validationStatus());
                    assertEquals(CAADNSClient.ValidationAssurance.TRUSTED_RESOLVER, result.responses().get(0).assurance());
                }
            }
        }
    }

    @Test
    void delegatedAliasFailureRetainsEarlierEvidenceAndNeverBecomesAbsence() throws Exception {
        try (Fixture dns = new Fixture(q -> q.getQuestion().getName().equals(name(NAME.asciiAbsoluteName()))
                ? reply(q, 0, cname(NAME.asciiAbsoluteName(), "edge.test.")) : reply(q, Rcode.SERVFAIL));
                var client = open(dns, true)) {
            var failure = assertThrows(DNSLookupException.class, () -> client.resolveCaa(NAME, budget())).failure();
            assertEquals(DNSLookupException.Reason.RCODE_FAILURE, failure.reason());
            assertEquals(2, failure.partialResponses().size());
            assertEquals(List.of(NAME.asciiAbsoluteName(), "edge.test."), dns.names());
        }
    }

    @Test
    void resolverDiagnosticsAreBoundedAndHaveControlCharactersRemoved() throws Exception {
        try (Fixture dns = new Fixture(q -> {
            var response = reply(q, Rcode.SERVFAIL);
            response.addRecord(new OPTRecord(1232, 0, 0, 0,
                    new ExtendedErrorCodeOption(6, "line\r\n\u0001" + "x".repeat(2000))), Section.ADDITIONAL);
            return response;
        }); var client = open(dns, true)) {
            var failure = assertThrows(DNSLookupException.class, () -> client.resolveCaa(NAME, budget())).failure();
            var diagnostic = failure.partialResponses().get(0).diagnostic().orElseThrow();
            assertEquals(6, diagnostic.code());
            assertEquals(1024, diagnostic.text().orElseThrow().length());
            assertFalse(diagnostic.text().orElseThrow().chars().anyMatch(Character::isISOControl));
            assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE, failure.reason());
        }
    }

    @Test
    void dnameAtTheQueriedOwnerDoesNotRedirectItsOwnCaaPolicy() throws Exception {
        try (Fixture dns = new Fixture(q -> reply(q, 0,
                new DNAMERecord(name(NAME.asciiAbsoluteName()), DClass.IN, 10, name("other.test.")),
                caa(NAME.asciiAbsoluteName(), "issuer.test".getBytes(java.nio.charset.StandardCharsets.US_ASCII))));
                var client = open(dns, false)) {
            var result = client.resolveCaa(NAME, budget());
            assertEquals(NAME, result.terminalName());
            assertTrue(result.aliases().isEmpty());
        }
    }

    @Test
    void dnameLifetimeCannotBeExtendedByItsSynthesizedCname() throws Exception {
        try (Fixture dns = new Fixture(q -> reply(q, 0,
                new DNAMERecord(name("customer.test."), DClass.IN, 7, name("provider.test.")),
                new CNAMERecord(name(NAME.asciiAbsoluteName()), DClass.IN, 200, name("www.provider.test.")),
                caa("www.provider.test.", new byte[] {'x'}))); var client = open(dns, false)) {
            assertEquals(7, client.resolveCaa(NAME, budget()).aliases().get(0).ttlSeconds());
        }
    }

    @Test
    void anAnswerInAnotherDnsClassCannotSupplyAuthorization() throws Exception {
        try (Fixture dns = new Fixture(q -> reply(q, 0,
                new CAARecord(name(NAME.asciiAbsoluteName()), DClass.CH, 60, 0, "issue", "issuer.test")));
                var client = open(dns, false)) {
            assertReason(DNSLookupException.Reason.MALFORMED_RESPONSE, () -> client.resolveCaa(NAME, budget()));
        }
    }

    @Test
    void missingQuestionsWrongTypesAndWrongOpcodesCannotProduceAResult() throws Exception {
        for (String variant : List.of("missing", "type", "opcode", "id")) {
            try (Fixture dns = new Fixture(q -> {
                var response = reply(q, 0, caa(NAME.asciiAbsoluteName(), new byte[] {'x'}));
                if (variant.equals("missing") || variant.equals("type")) {
                    response.removeAllRecords(Section.QUESTION);
                    if (variant.equals("type")) response.addRecord(Record.newRecord(name(NAME.asciiAbsoluteName()), Type.TXT, DClass.IN), Section.QUESTION);
                }
                if (variant.equals("opcode")) response.getHeader().setOpcode(Opcode.UPDATE);
                if (variant.equals("id")) response.getHeader().setID((q.getHeader().getID() + 1) & 65535);
                return response;
            }); var client = open(dns, false)) {
                var limited = new TestCAALookupBudget(new CAAPolicy.Limits(Duration.ofSeconds(1), Duration.ofMillis(150), 2, 2, 1));
                assertThrows(DNSLookupException.class, () -> client.resolveCaa(NAME, limited), variant);
            }
        }
    }

    @Test
    void concurrentCallsCannotMixResponseOwnersOrEvidence() throws Exception {
        var workers = Executors.newFixedThreadPool(4);
        try (Fixture dns = new Fixture(q -> reply(q, 0,
                caa(q.getQuestion().getName().toString(), new byte[] {'x'}))); var client = open(dns, false)) {
            var pending = new ArrayList<Future<CAADNSClient.LookupResult>>();
            for (int i = 0; i < 4; i++) {
                var candidate = new DNSDomainName("n" + i + ".customer.test.");
                pending.add(workers.submit(() -> client.resolveCaa(candidate, budget())));
            }
            for (int i = 0; i < pending.size(); i++) {
                var expected = new DNSDomainName("n" + i + ".customer.test.");
                var result = pending.get(i).get(3, TimeUnit.SECONDS);
                assertEquals(expected, result.candidate());
                assertEquals(expected, result.records().get(0).owner());
                assertEquals(expected, result.responses().get(0).question());
            }
        } finally { workers.shutdownNow(); }
    }

    private static CAADNSClient open(Fixture fixture, boolean delegated) throws DNSLookupException {
        return (delegated ? new DNSJavaCAAProvider.LocalValidatingResolver() : new DNSJavaCAAProvider())
                .open(fixture.config());
    }

    private static TestCAALookupBudget budget() {
        return new TestCAALookupBudget(new CAAPolicy.Limits(Duration.ofSeconds(3), Duration.ofSeconds(1), 10, 10, 2));
    }

    private static void assertReason(DNSLookupException.Reason expected, Action action) {
        assertEquals(expected, assertThrows(DNSLookupException.class, action::run).failure().reason());
    }

    private interface Action {
        void run() throws Exception;
    }

    private static Name name(String value) {
        return Name.fromConstantString(value);
    }

    private static CAARecord caa(String owner, byte[] value) {
        byte[] rdata = new byte[7 + value.length];
        rdata[1] = 5;
        System.arraycopy(new byte[] { 'i', 's', 's', 'u', 'e' }, 0, rdata, 2, 5);
        System.arraycopy(value, 0, rdata, 7, value.length);
        return (CAARecord) Record.newRecord(name(owner), Type.CAA, DClass.IN, 60, rdata);
    }

    private static CNAMERecord cname(String source, String target) {
        return new CNAMERecord(name(source), DClass.IN, 30, name(target));
    }

    private static SOARecord soa(String owner) {
        return new SOARecord(name(owner), DClass.IN, 30, name("ns.test."), name("admin.test."), 1, 60, 60, 60, 15);
    }

    private static Message reply(Message query, int rcode, Record... records) {
        Message response = new Message(query.getHeader().getID());
        response.getHeader().setFlag(Flags.QR);
        response.getHeader().setFlag(Flags.RA);
        response.getHeader().setRcode(rcode);
        response.addRecord(query.getQuestion(), Section.QUESTION);
        for (Record record : records) response.addRecord(record, Section.ANSWER);
        return response;
    }

    /** Bounded loopback TCP fixture; null responses simulate a silent resolver. */
    private static final class Fixture implements AutoCloseable {
        private final ServerSocket listener;
        private final Future<?> acceptor;
        private final ExecutorService workers = Executors.newCachedThreadPool(r -> {
            Thread thread = new Thread(r, "caa-dnsjava-fixture");
            thread.setDaemon(true);
            return thread;
        });
        private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
        private final AtomicReference<Throwable> failure = new AtomicReference<>();
        private final List<String> queries = new CopyOnWriteArrayList<>();

        Fixture(Function<Message, Message> handler) throws IOException {
            listener = new ServerSocket(0, 16, InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 }));
            acceptor = workers.submit(() -> {
                while (!listener.isClosed()) {
                    try {
                        Socket socket = listener.accept();
                        sockets.add(socket);
                        workers.submit(() -> serve(socket, handler));
                    } catch (SocketException e) {
                        if (!listener.isClosed()) failure.compareAndSet(null, e);
                    } catch (IOException e) {
                        failure.compareAndSet(null, e);
                    }
                }
            });
        }

        private void serve(Socket socket, Function<Message, Message> handler) {
            try (socket) {
                var input = new DataInputStream(socket.getInputStream());
                var output = new DataOutputStream(socket.getOutputStream());
                while (!listener.isClosed()) {
                    int length = input.readUnsignedShort();
                    byte[] bytes = input.readNBytes(length);
                    Message query = new Message(bytes);
                    queries.add(query.getQuestion().getName().toString());
                    assertTrue(Set.of(Type.CAA, Type.DNSKEY, Type.DS).contains(query.getQuestion().getType()));
                    Message response = handler.apply(query);
                    if (response != null) {
                        byte[] wire = response.toWire();
                        output.writeShort(wire.length);
                        output.write(wire);
                        output.flush();
                    }
                }
            } catch (EOFException | SocketException e) {
                // Closing the client or fixture terminates the connection.
            } catch (Throwable e) {
                failure.compareAndSet(null, e);
            } finally {
                sockets.remove(socket);
            }
        }

        List<String> names() {
            return List.copyOf(queries);
        }

        CAADNSClientProvider.Config config() {
            return new CAADNSClientProvider.Config(
                    Map.of("server", "127.0.0.1", "port", Integer.toString(listener.getLocalPort())));
        }

        @Override
        public void close() throws Exception {
            listener.close();
            acceptor.get(2, TimeUnit.SECONDS);
            for (Socket socket : sockets) socket.close();
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(2, TimeUnit.SECONDS));
            if (failure.get() != null) throw new AssertionError("DNS fixture failed", failure.get());
        }
    }
}
