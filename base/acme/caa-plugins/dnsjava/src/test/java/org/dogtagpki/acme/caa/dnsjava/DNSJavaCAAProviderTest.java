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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.function.UnaryOperator;

import org.dogtagpki.acme.caa.CAADNSClient;
import org.dogtagpki.acme.caa.CAADNSClientProvider;
import org.dogtagpki.acme.caa.CAADecision;
import org.dogtagpki.acme.caa.CAAIssuanceGate;
import org.dogtagpki.acme.caa.CAAIssuanceGate.CAAApprovalException;
import org.dogtagpki.acme.caa.CAAPolicy;
import org.dogtagpki.acme.caa.CAARequest;
import org.dogtagpki.acme.caa.DNSDomainName;
import org.dogtagpki.acme.caa.DNSLookupException;
import org.dogtagpki.acme.caa.TestCAALookupBudget;
import org.dogtagpki.acme.caa.TestCAAIssuance;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.CAARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNAMERecord;
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
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

/**
 * Tests the dnsjava adapter between the shared CAA engine and a DNS resolver.
 * A loopback TCP fixture returns controlled packets to exercise alias handling,
 * negative answers, response correlation, resource bounds and cancellation.
 * Gate tests also verify that rejected DNS data cannot reach issuer submission.
 *
 * The fixture models a trusted resolver; it does not validate DNSSEC signatures.
 * CAADNSSECIntegrationTest exercises actual validation through BIND and Unbound.
 */
@Timeout(10)
public class DNSJavaCAAProviderTest {

    private static final DNSDomainName NAME = new DNSDomainName("www.customer.test.");

    /**
     * Supply an invalid port containing private text. Initialization must retain
     * its parsing cause while keeping the configuration value out of the message.
     */
    @Test
    void preservesConfigurationCauseWithoutExposingSettingsInFailureMessage() {
        CAADNSClientProvider.Config config = new CAADNSClientProvider.Config(
                Map.of("server", "127.0.0.1", "port", "private value"));
        DNSLookupException error = assertThrows(DNSLookupException.class, () -> new DNSJavaCAAProvider().open(config));

        assertEquals(DNSLookupException.Reason.CONFIGURATION, error.failure().reason());
        assertTrue(error.getCause() instanceof NumberFormatException);
        assertFalse(error.getMessage().contains("private value"));
    }

    /**
     * Return binary CAA RDATA with AD set. Preserve the bytes, owner and TTL
     * and record the trusted resolver's authenticated-data classification.
     */
    @Test
    void preservesBinaryCaaAndTrustedResolverEvidence() throws Exception {
        try (Fixture dns = new Fixture(query -> {
            Message response = reply(query, Rcode.NOERROR, caa(NAME.asciiAbsoluteName(), new byte[] { 0, (byte) 255 }));
            response.getHeader().setFlag(Flags.AD);
            return response;
        }); CAADNSClient client = open(dns)) {
            CAADNSClient.LookupResult answer = client.resolveCaa(NAME, budget());

            assertEquals(CAADNSClient.LookupKind.RRSET, answer.kind());
            assertEquals(NAME, answer.records().get(0).owner());
            assertEquals(60, answer.records().get(0).ttlSeconds());
            assertArrayEquals(new byte[] { 0, (byte) 255 }, answer.records().get(0).value());
            assertTrue(answer.responses().get(0).authenticatedData());
            assertEquals(CAADNSClient.ValidationStatus.SECURE, answer.responses().get(0).validationStatus());
        }
    }

    /**
     * Return a CNAME first and a terminal CAA grant on the next query. The
     * adapter follows the target; parent discovery remains the engine's job.
     */
    @Test
    void followsAliasOnlyRepliesWithoutClimbingEitherParent() throws Exception {
        try (Fixture dns = new Fixture(query -> query.getQuestion().getName().toString().equals(NAME.asciiAbsoluteName())
                ? reply(query, 0, cname(NAME.asciiAbsoluteName(), "edge.provider.test."))
                : reply(query, 0, caa("edge.provider.test.", new byte[] { 'x' })));
                CAADNSClient client = open(dns)) {
            CAADNSClient.LookupResult answer = client.resolveCaa(NAME, budget());

            assertEquals(new DNSDomainName("edge.provider.test."), answer.terminalName());
            assertEquals(1, answer.aliases().size());
            assertEquals(2, answer.responses().size());
            assertEquals(List.of(NAME.asciiAbsoluteName(), "edge.provider.test."), dns.names());
        }
    }

    /**
     * Put an alias and terminal CAA data in one answer, with and without a
     * DNAME. Resolve both forms without sending an unnecessary second query.
     */
    @Test
    void acceptsCompleteCnameAndDnameChainsInOneReply() throws Exception {
        // Exercise a plain CNAME and a CNAME synthesized from DNAME with the same target.
        for (boolean includeDname : List.of(false, true)) {
            try (Fixture dns = new Fixture(query -> {
                List<Record> records = new ArrayList<>();
                if (includeDname) {
                    records.add(new DNAMERecord(name("customer.test."), DClass.IN, 45, name("provider.test.")));
                }

                records.add(cname(NAME.asciiAbsoluteName(), "www.provider.test."));
                records.add(caa("www.provider.test.", new byte[] { 'x' }));
                return reply(query, 0, records.toArray(Record[]::new));
            }); CAADNSClient client = open(dns)) {
                CAADNSClient.LookupResult answer = client.resolveCaa(NAME, budget());

                assertEquals(CAADNSClient.LookupKind.RRSET, answer.kind());
                assertEquals(includeDname ? CAADNSClient.AliasKind.DNAME_SYNTHESIS : CAADNSClient.AliasKind.CNAME,
                        answer.aliases().get(0).kind());
                assertEquals(1, dns.names().size());
            }
        }
    }

    /**
     * Return a DNAME and terminal CAA data without a synthesized CNAME. The
     * adapter must derive the target and retain the DNAME lifetime.
     */
    @Test
    void synthesizesDnameWhenTheReplyOmitsItsCname() throws Exception {
        try (Fixture dns = new Fixture(query -> reply(query, 0,
                new DNAMERecord(name("customer.test."), DClass.IN, 45, name("provider.test.")),
                caa("www.provider.test.", new byte[] { 'x' }))); CAADNSClient client = open(dns)) {
            CAADNSClient.LookupResult result = client.resolveCaa(NAME, budget());

            assertEquals(new DNSDomainName("www.provider.test."), result.terminalName());
            assertEquals(45, result.aliases().get(0).ttlSeconds());
        }
    }

    /**
     * Exercise a CNAME that contradicts its DNAME, then a two-name CNAME
     * cycle. Neither malformed synthesis nor looping discovery may succeed.
     */
    @Test
    void rejectsInvalidDnameSynthesisAndAliasLoops() throws Exception {
        try (Fixture dns = new Fixture(query -> reply(query, 0,
                new DNAMERecord(name("customer.test."), DClass.IN, 45, name("provider.test.")),
                cname(NAME.asciiAbsoluteName(), "wrong.test."))); CAADNSClient client = open(dns)) {
            assertReason(DNSLookupException.Reason.MALFORMED_RESPONSE, () -> client.resolveCaa(NAME, budget()));
        }

        try (Fixture dns = new Fixture(query -> {
            String source = query.getQuestion().getName().toString();
            String target = source.equals(NAME.asciiAbsoluteName()) ? "edge.test." : NAME.asciiAbsoluteName();
            return reply(query, 0, cname(source, target));
        });
                CAADNSClient client = open(dns)) {
            assertReason(DNSLookupException.Reason.ALIAS_LOOP, () -> client.resolveCaa(NAME, budget()));
        }
    }

    /**
     * Return empty recursive answers with and without an SOA. Both establish
     * NODATA; only the SOA case supplies negative-cache lifetime metadata.
     */
    @Test
    void preservesNodataSoaAndAcceptsExplicitEmptyRecursiveAnswers() throws Exception {
        for (boolean includeSoa : List.of(false, true)) {
            try (Fixture dns = new Fixture(query -> {
                Message response = reply(query, 0);
                if (includeSoa) {
                    response.addRecord(soa("customer.test."), Section.AUTHORITY);
                }

                return response;
            }); CAADNSClient client = open(dns)) {
                CAADNSClient.LookupResult result = client.resolveCaa(NAME, budget());

                assertEquals(CAADNSClient.LookupKind.NODATA, result.kind());
                assertEquals(includeSoa, result.negativeSoa().isPresent());
                if (includeSoa) {
                    CAADNSClient.SOAEvidence soa = result.negativeSoa().orElseThrow();

                    assertEquals(30, soa.ttlSeconds());
                    assertEquals(15, soa.minimumSeconds());
                }
            }
        }
    }

    /**
     * Configure a numeric non-loopback resolver. Reject initialization with a
     * useful explanation that does not expose the configured address.
     */
    @Test
    void explainsTheLoopbackRequirementWithoutExposingTheEndpoint() {
        DNSLookupException error = assertThrows(DNSLookupException.class,
                () -> new DNSJavaCAAProvider().open(
                        new CAADNSClientProvider.Config(Map.of("server", "192.0.2.1"))));
        assertEquals(DNSLookupException.Reason.CONFIGURATION, error.failure().reason());
        assertEquals("Delegated DNSSEC requires a loopback resolver address", error.getMessage());
        assertFalse(error.getMessage().contains("192.0.2.1"));
    }

    /**
     * Return a CAA signature without CAA data. A signature by itself cannot
     * establish a complete RRset or absence and must not permit parent search.
     */
    @Test
    void rejectsSignatureOnlyAnswersWithoutTreatingThemAsAbsence() throws Exception {
        try (Fixture dns = new Fixture(query -> reply(query, Rcode.NOERROR,
                new RRSIGRecord(name(NAME.asciiAbsoluteName()), DClass.IN, 60,
                        Type.CAA, 8, 60, Instant.now().plusSeconds(60),
                        Instant.now().minusSeconds(60), 1, name("customer.test."), new byte[] { 1 })));
                CAADNSClient client = open(dns)) {
            assertReason(DNSLookupException.Reason.INCOMPLETE_ANSWER,
                    () -> client.resolveCaa(NAME, budget()));
        }
    }

    /**
     * Return a CNAME and NXDOMAIN together. Record absence at the target
     * without querying it again or climbing a parent inside the adapter.
     */
    @Test
    void identifiesNxdomainAtTheAliasTargetWithoutRequerying() throws Exception {
        try (Fixture dns = new Fixture(query -> reply(query, Rcode.NXDOMAIN,
                cname(NAME.asciiAbsoluteName(), "missing.provider.test."))); CAADNSClient client = open(dns)) {
            CAADNSClient.LookupResult result = client.resolveCaa(NAME, budget());

            assertEquals(CAADNSClient.LookupKind.NXDOMAIN, result.kind());
            assertEquals(new DNSDomainName("missing.provider.test."), result.terminalName());
            assertEquals(1, dns.names().size());
        }
    }

    /**
     * Return a referral, unrelated positive data or an unrelated negative SOA.
     * Each lacks relevant complete CAA evidence and must fail as incomplete.
     */
    @Test
    void rejectsReferralsUnrelatedAnswersAndMismatchedNegativeOwners() throws Exception {
        for (String scenario : List.of("referral", "unrelated-answer", "unrelated-soa")) {
            try (Fixture dns = new Fixture(query -> {
                Message response = reply(query, 0);
                if (scenario.equals("referral")) {
                    response.addRecord(new NSRecord(name("customer.test."), DClass.IN, 30, name("ns.test.")),
                            Section.AUTHORITY);
                }

                if (scenario.equals("unrelated-answer")) {
                    response.addRecord(caa("unrelated.test.", new byte[] { 'x' }), Section.ANSWER);
                }

                if (scenario.equals("unrelated-soa")) {
                    response.addRecord(soa("unrelated.test."), Section.AUTHORITY);
                }

                return response;
            }); CAADNSClient client = open(dns)) {
                assertReason(DNSLookupException.Reason.INCOMPLETE_ANSWER, () -> client.resolveCaa(NAME, budget()));
            }
        }
    }

    /**
     * A contradictory NXDOMAIN or an unrelated answer with an SOA must fail
     * before parent discovery can turn apparent absence into permission to issue.
     */
    @Test
    void contradictoryNegativeAnswersSuppressSubmission() throws Exception {
        // Cover both misleading absence signals: unrelated data with SOA,
        // and NXDOMAIN contradicted by an address record for the queried name.
        for (int rcode : List.of(Rcode.NOERROR, Rcode.NXDOMAIN)) {
            try (Fixture dns = new Fixture(query -> {
                Message response;
                if (rcode == Rcode.NXDOMAIN) {
                    response = reply(query, rcode, new ARecord(query.getQuestion().getName(),
                            DClass.IN, 60, InetAddress.getLoopbackAddress()));
                } else {
                    response = reply(query, rcode, caa("unrelated.test.", new byte[] { 'x' }));
                    response.addRecord(soa("customer.test."), Section.AUTHORITY);
                }
                return response;
            })) {
                Properties properties = configuration(dns);
                AtomicInteger submissions = new AtomicInteger();

                try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties, getClass().getClassLoader())) {
                    CAARequest request = new CAARequest(List.of(new CAARequest.CertificateName(NAME, false)), Map.of());
                    CAAApprovalException failure = assertThrows(CAAApprovalException.class,
                            () -> TestCAAIssuance.submit(gate, request, decision -> {}, submissions::incrementAndGet));

                    assertEquals(CAADecision.Outcome.ERROR, failure.decision().outcome());
                    assertEquals(DNSLookupException.Reason.INCOMPLETE_ANSWER,
                            failure.decision().names().get(0).failure().orElseThrow().reason());
                    // Check both effects of rejection: no issuer call and no parent
                    // lookup that could turn the malformed answer into authorization.
                    assertEquals(0, submissions.get());
                    assertEquals(List.of(NAME.asciiAbsoluteName()), dns.names());
                }
            }
        }
    }

    /**
     * Negative answers can contain a signed alias chain. Its RRSIG is valid
     * answer metadata and must not be mistaken for unrelated terminal data.
     */
    @Test
    void acceptsSignedAliasInNegativeAnswers() throws Exception {
        for (int rcode : List.of(Rcode.NOERROR, Rcode.NXDOMAIN)) {
            try (Fixture dns = new Fixture(query -> {
                Message response = reply(query, rcode,
                        cname(NAME.asciiAbsoluteName(), "missing.customer.test."),
                        new RRSIGRecord(name(NAME.asciiAbsoluteName()), DClass.IN, 30,
                                Type.CNAME, 8, 30, Instant.now().plusSeconds(60),
                                Instant.now().minusSeconds(60), 1, name("customer.test."), new byte[] { 1 }));
                response.addRecord(soa("customer.test."), Section.AUTHORITY);
                return response;
            }); CAADNSClient client = open(dns)) {
                CAADNSClient.LookupResult result = client.resolveCaa(NAME, budget());

                assertEquals(rcode == Rcode.NXDOMAIN ? CAADNSClient.LookupKind.NXDOMAIN
                        : CAADNSClient.LookupKind.NODATA, result.kind());
                assertEquals(new DNSDomainName("missing.customer.test."), result.terminalName());
                assertEquals(1, result.aliases().size());
            }
        }
    }

    /**
     * Attach a signature that does not describe the alias in a negative answer.
     * A mismatched owner, DNS class or covered type is unrelated answer data,
     * even when an SOA would otherwise establish absence at the alias target.
     */
    @Test
    void rejectsNegativeAliasSignaturesWithMismatchedMetadata() throws Exception {
        // Change one signature field at a time so no other mismatch masks it.
        for (String scenario : List.of("owner", "class", "covered-type")) {
            try (Fixture dns = new Fixture(query -> {
                Name signatureOwner = scenario.equals("owner") ? name("other.customer.test.")
                        : name(NAME.asciiAbsoluteName());
                int signatureClass = scenario.equals("class") ? DClass.CH : DClass.IN;
                int coveredType = scenario.equals("covered-type") ? Type.CAA : Type.CNAME;
                RRSIGRecord signature = new RRSIGRecord(signatureOwner, signatureClass, 30,
                        coveredType, 8, 30, Instant.now().plusSeconds(60),
                        Instant.now().minusSeconds(60), 1, name("customer.test."), new byte[] { 1 });
                Message response = reply(query, Rcode.NOERROR,
                        cname(NAME.asciiAbsoluteName(), "missing.customer.test."), signature);
                response.addRecord(soa("customer.test."), Section.AUTHORITY);
                return response;
            }); CAADNSClient client = open(dns)) {
                DNSLookupException error = assertThrows(DNSLookupException.class,
                        () -> client.resolveCaa(NAME, budget()), scenario);

                // Wrong-class records at the current owner fail before absence classification.
                DNSLookupException.Reason expected = scenario.equals("class")
                        ? DNSLookupException.Reason.MALFORMED_RESPONSE
                        : DNSLookupException.Reason.INCOMPLETE_ANSWER;
                assertEquals(expected, error.failure().reason(), scenario);
                assertEquals(1, dns.names().size(), scenario);
            }
        }
    }

    /**
     * Return SERVFAIL and then a truncated TCP response. Preserve the resolver
     * error as failure; truncation must not become apparent record absence.
     */
    @Test
    void preservesServfailAsFailureAndRejectsTruncatedTcp() throws Exception {
        try (Fixture dns = new Fixture(query -> reply(query, Rcode.SERVFAIL)); CAADNSClient client = open(dns)) {
            DNSLookupException e = assertThrows(DNSLookupException.class, () -> client.resolveCaa(NAME, budget()));

            assertEquals(DNSLookupException.Reason.RCODE_FAILURE, e.failure().reason());
            assertEquals(Rcode.SERVFAIL, e.failure().partialResponses().get(0).rcode());
        }

        try (Fixture dns = new Fixture(query -> {
            Message response = reply(query, 0);
            response.getHeader().setFlag(Flags.TC);
            return response;
        }); CAADNSClient client = open(dns)) {
            assertReason(DNSLookupException.Reason.INCOMPLETE_ANSWER, () -> client.resolveCaa(NAME, budget()));
        }
    }

    /**
     * Check outgoing recursion, AD, DO and CD flags. Return an AD-clear alias
     * followed by an AD-set grant and retain each observation separately.
     */
    @Test
    void validatesDelegatedFlagsAndRetainsMixedAdEvidence() throws Exception {
        try (Fixture dns = new Fixture(query -> {
            assertTrue(query.getHeader().getFlag(Flags.RD));
            assertTrue(query.getHeader().getFlag(Flags.AD));
            assertFalse(query.getHeader().getFlag(Flags.CD));
            assertTrue((query.getOPT().getFlags() & ExtendedFlags.DO) != 0);
            boolean first = query.getQuestion().getName().toString().equals(NAME.asciiAbsoluteName());
            Message response = first ? reply(query, 0, cname(NAME.asciiAbsoluteName(), "edge.test."))
                    : reply(query, 0, caa("edge.test.", new byte[] { 'x' }));
            if (!first) {
                response.getHeader().setFlag(Flags.AD);
            }

            return response;
        }); CAADNSClient client = open(dns)) {
            CAADNSClient.LookupResult result = client.resolveCaa(NAME, budget());

            assertEquals(CAADNSClient.ValidationStatus.UNCLASSIFIED, result.responses().get(0).validationStatus());
            assertEquals(CAADNSClient.ValidationStatus.SECURE, result.responses().get(1).validationStatus());
        }
    }

    /**
     * Attach DNSSEC EDE codes 5-12 to SERVFAIL and classify validation failure.
     * EDE 22 and plain SERVFAIL remain resolver errors, not inferred DNSSEC proof.
     */
    @Test
    void delegatedDnssecErrorIsTypedWithoutGuessingFromServfailOrAdClear() throws Exception {
        for (int code : List.of(5, 6, 7, 8, 9, 10, 11, 12, 22)) {
            try (Fixture dns = new Fixture(query -> {
                Message response = reply(query, Rcode.SERVFAIL);
                OPTRecord opt = new OPTRecord(1232, 0, 0, 0,
                        new ExtendedErrorCodeOption(code, "fixture diagnostic"));
                response.addRecord(opt, Section.ADDITIONAL);
                return response;
            }); CAADNSClient client = open(dns)) {
                DNSLookupException error = assertThrows(DNSLookupException.class,
                        () -> client.resolveCaa(NAME, budget()));
                DNSLookupException.Failure failure = error.failure();

                assertEquals(code == 22 ? DNSLookupException.Reason.RCODE_FAILURE
                        : DNSLookupException.Reason.VALIDATION_FAILURE, failure.reason());
                assertEquals(code, failure.partialResponses().get(0).diagnostic().orElseThrow().code());
            }
        }

        try (Fixture dns = new Fixture(query -> reply(query, Rcode.SERVFAIL)); CAADNSClient client = open(dns)) {
            assertReason(DNSLookupException.Reason.RCODE_FAILURE, () -> client.resolveCaa(NAME, budget()));
        }
    }

    /**
     * Pass unsupported settings and a hostname, then a remote numeric endpoint.
     * The provider must reject settings outside its server/port contract.
     */
    @Test
    void rejectsBehaviorKnobsAndInvalidEndpoints() {
        DNSJavaCAAProvider provider = new DNSJavaCAAProvider();
        for (Map<String, String> settings : List.of(
                Map.of("server", "127.0.0.1", "validationMode", "DELEGATED_ENFORCING"),
                Map.of("server", "127.0.0.1", "trustValidatingResolver", "true"),
                Map.of("server", "127.0.0.1", "version", "1"),
                Map.of("server", "resolver.test"),
                Map.of("server", "127.0.0.1", "unknown", "true"))) {
            assertReason(DNSLookupException.Reason.CONFIGURATION,
                    () -> provider.open(new CAADNSClientProvider.Config(settings)));
        }

        assertReason(DNSLookupException.Reason.CONFIGURATION,
                () -> new DNSJavaCAAProvider().open(
                        new CAADNSClientProvider.Config(Map.of("server", "8.8.8.8"))));
    }

    /**
     * Omit the required server or supply a port outside the TCP range.
     * Configuration must fail before any DNS lookup can start.
     */
    @Test
    void rejectsMissingServerAndOutOfRangePorts() {
        DNSJavaCAAProvider provider = new DNSJavaCAAProvider();
        List<Map<String, String>> invalidSettings = List.of(
                Map.<String, String>of(),
                Map.of("port", "53"),
                Map.of("server", "127.0.0.1", "port", "0"),
                Map.of("server", "127.0.0.1", "port", "-1"),
                Map.of("server", "127.0.0.1", "port", "65536"));

        for (Map<String, String> settings : invalidSettings) {
            DNSLookupException error = assertThrows(DNSLookupException.class,
                    () -> provider.open(new CAADNSClientProvider.Config(settings)));

            assertEquals(DNSLookupException.Reason.CONFIGURATION, error.failure().reason(), settings.toString());
        }
    }

    /**
     * Accept both compressed and expanded numeric IPv6 loopback addresses.
     * Opening and closing a client does not need a listening DNS server.
     */
    @Test
    void acceptsNumericIpv6LoopbackEndpoints() throws Exception {
        DNSJavaCAAProvider provider = new DNSJavaCAAProvider();
        for (String server : List.of("::1", "0:0:0:0:0:0:0:1")) {
            CAADNSClientProvider.Config config = new CAADNSClientProvider.Config(
                    Map.of("server", server, "port", "65535"));

            try (CAADNSClient client = provider.open(config)) {
                // Closing twice is harmless, even when the client has sent no queries.
                client.close();
            }
        }
    }

    /**
     * Return two CNAME targets, or CNAME and CAA at the same owner. Reject
     * ambiguous terminal policy instead of selecting an arbitrary answer.
     */
    @Test
    void rejectsConflictingAliasesAndCaaAlongsideAnAlias() throws Exception {
        for (boolean withCaa : List.of(false, true)) {
            try (Fixture dns = new Fixture(query -> reply(query, 0,
                    cname(NAME.asciiAbsoluteName(), "one.test."), withCaa
                        ? caa(NAME.asciiAbsoluteName(), new byte[] { 'x' })
                        : cname(NAME.asciiAbsoluteName(), "two.test.")));
                    CAADNSClient client = open(dns)) {
                assertReason(DNSLookupException.Reason.MALFORMED_RESPONSE, () -> client.resolveCaa(NAME, budget()));
            }
        }
    }

    /**
     * Alter the echoed question, clear recursion availability or set CD.
     * Reject responses that cannot satisfy the configured resolver contract.
     */
    @Test
    void rejectsMismatchedQuestionsAndNonrecursiveOrCdResponses() throws Exception {
        for (String scenario : List.of("wrong-question", "no-recursion", "checking-disabled")) {
            try (Fixture dns = new Fixture(query -> {
                Message response = reply(query, 0);
                if (scenario.equals("wrong-question")) {
                    response.removeAllRecords(Section.QUESTION);
                    response.addRecord(Record.newRecord(name("wrong.test."), Type.CAA, DClass.IN), Section.QUESTION);
                }

                if (scenario.equals("no-recursion")) {
                    response.getHeader().unsetFlag(Flags.RA);
                }
                if (scenario.equals("checking-disabled")) {
                    response.getHeader().setFlag(Flags.CD);
                }

                return response;
            }); CAADNSClient client = open(dns)) {
                assertReason(scenario.equals("wrong-question") ? DNSLookupException.Reason.MALFORMED_RESPONSE
                        : DNSLookupException.Reason.INCOMPLETE_ANSWER, () -> client.resolveCaa(NAME, budget()));
            }
        }
    }

    /**
     * Return more actual records than the adapter permits, first in each
     * section and then spread across sections. The combined parsed count must
     * fail as LIMIT_EXCEEDED before interpreting any of the records.
     */
    @Test
    void refusesOversizedRecordSections() throws Exception {
        for (int section : List.of(Section.ANSWER, Section.AUTHORITY, Section.ADDITIONAL)) {
            try (Fixture dns = new Fixture(query -> {
                Message response = reply(query, 0);
                addCaaRecords(response, section, 1025);
                return response;
            }); CAADNSClient client = open(dns)) {
                assertReason(DNSLookupException.Reason.LIMIT_EXCEEDED, () -> client.resolveCaa(NAME, budget()));
            }
        }

        // Each section is below the limit, but their combined count is 1025.
        // Supply real records so this exercises the adapter's parsed-data limit.
        try (Fixture dns = new Fixture(query -> {
            Message response = reply(query, 0);
            addCaaRecords(response, Section.ANSWER, 512);
            addCaaRecords(response, Section.AUTHORITY, 512);
            addCaaRecords(response, Section.ADDITIONAL, 1);
            return response;
        }); CAADNSClient client = open(dns)) {
            assertReason(DNSLookupException.Reason.LIMIT_EXCEEDED, () -> client.resolveCaa(NAME, budget()));
        }
    }

    /**
     * Map dnsjava's rejection of a short header or an incomplete question
     * section to MALFORMED_RESPONSE. A later healthy reply must remain usable.
     */
    @Test
    void rejectsMalformedHeadersAndRecovers() throws Exception {
        for (boolean shortHeader : List.of(false, true)) {
            AtomicBoolean corrupt = new AtomicBoolean(true);
            try (Fixture dns = new Fixture(query -> reply(query, 0,
                    caa(NAME.asciiAbsoluteName(), new byte[] { 'x' })), wire -> {
                if (!corrupt.get()) {
                    return wire;
                }
                byte[] header = Arrays.copyOf(wire, shortHeader ? 11 : 12);
                if (!shortHeader) {
                    ByteBuffer.wrap(header).putShort(4, (short) 65535);
                }
                return header;
            }); CAADNSClient client = open(dns)) {
                assertReason(DNSLookupException.Reason.MALFORMED_RESPONSE,
                        () -> client.resolveCaa(NAME, budget()));

                corrupt.set(false);
                assertEquals(CAADNSClient.LookupKind.RRSET, client.resolveCaa(NAME, budget()).kind());
            }
        }
    }

    /**
     * Accept exactly the permitted parsed record count and preserve a large
     * CAA value carried over TCP. Valid replies are not subject to a UDP-size limit.
     */
    @Test
    void acceptsRecordLimitAndLargeTcpValues() throws Exception {
        try (Fixture dns = new Fixture(query -> {
            Message response = reply(query, 0, caa(NAME.asciiAbsoluteName(), new byte[] { 'x' }));
            // One answer plus 1023 additional records reaches the limit exactly.
            for (int index = 0; index < 1023; index++) {
                response.addRecord(caa("r" + index + ".test.", new byte[] { 'x' }), Section.ADDITIONAL);
            }
            return response;
        }); CAADNSClient client = open(dns)) {
            assertEquals(CAADNSClient.LookupKind.RRSET, client.resolveCaa(NAME, budget()).kind());
        }

        byte[] value = new byte[16384];
        Arrays.fill(value, (byte) 'x');
        try (Fixture dns = new Fixture(query -> reply(query, 0, caa(NAME.asciiAbsoluteName(), value)));
                CAADNSClient client = open(dns)) {
            CAADNSClient.LookupResult result = client.resolveCaa(NAME, budget());

            assertArrayEquals(value, result.records().get(0).value());
        }
    }

    /**
     * Allow only one query, then return an alias that needs a second. Reject
     * the follow-up while retaining evidence from the completed first exchange.
     */
    @Test
    void sharesBudgetsAcrossAliasQueriesAndRetainsPartialEvidence() throws Exception {
        try (Fixture dns = new Fixture(query -> reply(query, 0, cname(NAME.asciiAbsoluteName(), "edge.test.")));
                CAADNSClient client = open(dns)) {
            TestCAALookupBudget limited = new TestCAALookupBudget(
                    new CAAPolicy.Limits(Duration.ofSeconds(2), Duration.ofSeconds(1), 1, 3, 1));
            DNSLookupException e = assertThrows(DNSLookupException.class, () -> client.resolveCaa(NAME, limited));

            assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED, e.failure().reason());
            assertEquals(1, e.failure().partialResponses().size());
            assertEquals(1, dns.names().size());
        }
    }

    /**
     * Return two alias transitions and terminal CAA data in one reply. A single
     * exchange must still consume both alias reservations before returning data.
     */
    @Test
    void enforcesAliasBudgetWithinOneResponse() throws Exception {
        try (Fixture dns = new Fixture(query -> reply(query, 0,
                cname(NAME.asciiAbsoluteName(), "edge.test."),
                cname("edge.test.", "terminal.test."),
                caa("terminal.test.", new byte[] { 'x' })));
                CAADNSClient client = open(dns)) {
            TestCAALookupBudget limited = new TestCAALookupBudget(
                    new CAAPolicy.Limits(Duration.ofSeconds(2), Duration.ofSeconds(1), 1, 1, 1));

            DNSLookupException error = assertThrows(DNSLookupException.class,
                    () -> client.resolveCaa(NAME, limited));

            assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED, error.failure().reason());
            assertEquals(1, error.failure().partialResponses().size());
            assertEquals(List.of(NAME.asciiAbsoluteName()), dns.names());

            // The same response succeeds when both alias transitions are allowed.
            TestCAALookupBudget exact = new TestCAALookupBudget(
                    new CAAPolicy.Limits(Duration.ofSeconds(2), Duration.ofSeconds(1), 1, 2, 1));
            CAADNSClient.LookupResult result = client.resolveCaa(NAME, exact);

            assertEquals(CAADNSClient.LookupKind.RRSET, result.kind());
            assertEquals(new DNSDomainName("terminal.test."), result.terminalName());
            assertEquals(2, result.aliases().size());
            assertEquals(1, result.responses().size());
        }
    }

    /**
     * Keep header counts valid while corrupting CAA RDATA or creating a name
     * compression loop. dnsjava parsing must fail as MALFORMED_RESPONSE, and
     * the client must recover when a later response contains valid record data.
     */
    @Test
    void malformedRecordDataFailsAndHealthyResponsesRecover() throws Exception {
        // The answer starts immediately after the echoed question in this fixture.
        int answerOffset = Message.newQuery(Record.newRecord(name(NAME.asciiAbsoluteName()),
                Type.CAA, DClass.IN)).toWire().length;
        for (String scenario : List.of("truncated-rdata", "compression-loop")) {
            AtomicBoolean corrupt = new AtomicBoolean(true);
            try (Fixture dns = new Fixture(query -> reply(query, 0,
                    caa(NAME.asciiAbsoluteName(), new byte[] { 'x', 'y' })), wire -> {
                if (!corrupt.get()) {
                    return wire;
                }
                if (scenario.equals("truncated-rdata")) {
                    // Preserve the declared RDLENGTH while removing its final octet.
                    return Arrays.copyOf(wire, wire.length - 1);
                }

                byte[] malformed = wire.clone();
                // RFC 1035 compression pointer: redirect the answer owner to itself.
                ByteBuffer.wrap(malformed).putShort(answerOffset, (short) (0xc000 | answerOffset));
                return malformed;
            }); CAADNSClient client = open(dns)) {
                DNSLookupException error = assertThrows(DNSLookupException.class,
                        () -> client.resolveCaa(NAME, budget()), scenario);

                assertEquals(DNSLookupException.Reason.MALFORMED_RESPONSE, error.failure().reason(), scenario);
                assertEquals(1, dns.names().size(), scenario);

                // Reuse the same client to prove a parse failure does not leave
                // later lookups cancelled or unable to acquire transport admission.
                corrupt.set(false);
                CAADNSClient.LookupResult recovered = client.resolveCaa(NAME, budget());

                assertEquals(CAADNSClient.LookupKind.RRSET, recovered.kind(), scenario);
                assertArrayEquals(new byte[] { 'x', 'y' }, recovered.records().get(0).value(), scenario);
                assertEquals(2, dns.names().size(), scenario);
            }
        }
    }

    /**
     * Leave a TCP query unanswered, then close the client. The first lookup
     * must time out and subsequent use of the closed client must be cancelled.
     */
    @Test
    void timesOutAndRejectsCallsAfterClose() throws Exception {
        try (Fixture dns = new Fixture(query -> null); CAADNSClient client = open(dns)) {
            TestCAALookupBudget limited = new TestCAALookupBudget(
                    new CAAPolicy.Limits(Duration.ofMillis(300), Duration.ofMillis(150), 2, 2, 1));
            assertReason(DNSLookupException.Reason.TIMEOUT, () -> client.resolveCaa(NAME, limited));
            client.close();
            assertReason(DNSLookupException.Reason.CANCELLED, () -> client.resolveCaa(NAME, budget()));
        }
    }

    /**
     * Wait until the fixture receives a query before closing the client.
     * The waiting worker must receive cancellation without waiting for DNS.
     */
    @Test
    void cancelsAnActiveQueryOnClose() throws Exception {
        CountDownLatch received = new CountDownLatch(1);
        try (Fixture dns = new Fixture(query -> {
            received.countDown();
            return null;
        }); CAADNSClient client = open(dns)) {
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                Future<DNSLookupException> result = worker.submit(() ->
                        assertThrows(DNSLookupException.class, () -> client.resolveCaa(NAME, budget())));
                assertTrue(received.await(2, TimeUnit.SECONDS));
                client.close();
                assertEquals(DNSLookupException.Reason.CANCELLED, result.get(2, TimeUnit.SECONDS).failure().reason());
            } finally {
                worker.shutdownNow();
            }
        }
    }

    /**
     * Open the adapter through configured class loading and the real gate.
     * An issuer grant reaches the recording issuer; an empty grant blocks it.
     */
    @Test
    void loadsTheOptionalAdapterByClassNameWithoutDnsjavaTypesInTheEngine() throws Exception {
        AtomicInteger submitted = new AtomicInteger();
        for (String issuer : List.of("issuer.test", ";")) {
            try (Fixture dns = new Fixture(query -> reply(query, 0,
                    caa(NAME.asciiAbsoluteName(), issuer.getBytes(StandardCharsets.US_ASCII))))) {
                Properties properties = configuration(dns);
                try (CAAIssuanceGate gate = CAAIssuanceGate.open(properties, getClass().getClassLoader())) {
                    CAARequest request = new CAARequest(List.of(new CAARequest.CertificateName(NAME, false)), Map.of());
                    if (issuer.equals(";")) {
                        assertThrows(CAAApprovalException.class,
                                () -> TestCAAIssuance.submit(gate, request, d -> {}, submitted::incrementAndGet));
                    } else {
                        assertEquals(1, TestCAAIssuance.submit(gate, request,
                                d -> assertEquals(1, d.names().get(0).discovery().size()), submitted::incrementAndGet));
                    }
                }
            }
        }

        assertEquals(1, submitted.get());
    }

    /**
     * Exercise NODATA and NXDOMAIN with AD set and clear. Preserve the
     * resolver classification without treating AD-clear success as proven insecurity.
     */
    @Test
    void delegatedNegativeAnswersRetainSecureOrUnclassifiedStatus() throws Exception {
        // Cross absence kind with AD status: neither NXDOMAIN nor NODATA
        // alone determines whether the trusted resolver authenticated the data.
        for (boolean ad : List.of(false, true)) {
            for (int rcode : List.of(Rcode.NOERROR, Rcode.NXDOMAIN)) {
                try (Fixture dns = new Fixture(query -> {
                    Message response = reply(query, rcode);
                    response.addRecord(soa("customer.test."), Section.AUTHORITY);
                    if (ad) {
                        response.getHeader().setFlag(Flags.AD);
                    }

                    return response;
                }); CAADNSClient client = open(dns)) {
                    CAADNSClient.LookupResult result = client.resolveCaa(NAME, budget());
                    CAADNSClient.LookupKind expectedKind = rcode == Rcode.NXDOMAIN
                            ? CAADNSClient.LookupKind.NXDOMAIN : CAADNSClient.LookupKind.NODATA;
                    assertEquals(expectedKind, result.kind());
                    assertEquals(ad ? CAADNSClient.ValidationStatus.SECURE : CAADNSClient.ValidationStatus.UNCLASSIFIED,
                            result.responses().get(0).validationStatus());
                }
            }
        }
    }

    /**
     * Resolve an alias, then fail its target with SERVFAIL. Keep both
     * observations and report an error instead of authorizing through absence.
     */
    @Test
    void delegatedAliasFailureRetainsEarlierEvidenceAndNeverBecomesAbsence() throws Exception {
        try (Fixture dns = new Fixture(query -> query.getQuestion().getName().equals(name(NAME.asciiAbsoluteName()))
                ? reply(query, 0, cname(NAME.asciiAbsoluteName(), "edge.test.")) : reply(query, Rcode.SERVFAIL));
                CAADNSClient client = open(dns)) {
            DNSLookupException error = assertThrows(DNSLookupException.class,
                    () -> client.resolveCaa(NAME, budget()));
            DNSLookupException.Failure failure = error.failure();

            assertEquals(DNSLookupException.Reason.RCODE_FAILURE, failure.reason());
            assertEquals(2, failure.partialResponses().size());
            assertEquals(List.of(NAME.asciiAbsoluteName(), "edge.test."), dns.names());
        }
    }

    /**
     * Return oversized EDE text containing control characters. Retain its
     * error code while bounding and sanitizing the diagnostic text.
     */
    @Test
    void resolverDiagnosticsAreBoundedAndHaveControlCharactersRemoved() throws Exception {
        try (Fixture dns = new Fixture(query -> {
            Message response = reply(query, Rcode.SERVFAIL);
            response.addRecord(new OPTRecord(1232, 0, 0, 0,
                    new ExtendedErrorCodeOption(6, "line\r\n\u0001" + "x".repeat(2000))), Section.ADDITIONAL);
            return response;
        }); CAADNSClient client = open(dns)) {
            DNSLookupException error = assertThrows(DNSLookupException.class,
                    () -> client.resolveCaa(NAME, budget()));
            DNSLookupException.Failure failure = error.failure();
            CAADNSClient.ExtendedError diagnostic = failure.partialResponses().get(0).diagnostic().orElseThrow();

            assertEquals(6, diagnostic.code());
            assertEquals(1024, diagnostic.text().orElseThrow().length());
            assertFalse(diagnostic.text().orElseThrow().chars().anyMatch(Character::isISOControl));
            assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE, failure.reason());
        }
    }

    /**
     * Return DNAME at the queried owner together with its CAA record. DNAME
     * redirects descendants, so this owner's CAA policy remains applicable.
     */
    @Test
    void dnameAtTheQueriedOwnerDoesNotRedirectItsOwnCaaPolicy() throws Exception {
        try (Fixture dns = new Fixture(query -> reply(query, 0,
                new DNAMERecord(name(NAME.asciiAbsoluteName()), DClass.IN, 10, name("other.test.")),
                caa(NAME.asciiAbsoluteName(), "issuer.test".getBytes(StandardCharsets.US_ASCII))));
                CAADNSClient client = open(dns)) {
            CAADNSClient.LookupResult result = client.resolveCaa(NAME, budget());

            assertEquals(NAME, result.terminalName());
            assertTrue(result.aliases().isEmpty());
        }
    }

    /**
     * Give a synthesized CNAME a longer TTL than its DNAME. Retain the shorter
     * lifetime so synthesis cannot extend the underlying alias evidence.
     */
    @Test
    void dnameLifetimeCannotBeExtendedByItsSynthesizedCname() throws Exception {
        try (Fixture dns = new Fixture(query -> reply(query, 0,
                new DNAMERecord(name("customer.test."), DClass.IN, 7, name("provider.test.")),
                new CNAMERecord(name(NAME.asciiAbsoluteName()), DClass.IN, 200, name("www.provider.test.")),
                caa("www.provider.test.", new byte[] { 'x' }))); CAADNSClient client = open(dns)) {
            assertEquals(7, client.resolveCaa(NAME, budget()).aliases().get(0).ttlSeconds());
        }
    }

    /**
     * Return CAA data in the CHAOS class for an IN query. Reject it instead
     * of authorizing issuance using data from another DNS class.
     */
    @Test
    void anAnswerInAnotherDnsClassCannotSupplyAuthorization() throws Exception {
        try (Fixture dns = new Fixture(query -> reply(query, 0,
                new CAARecord(name(NAME.asciiAbsoluteName()), DClass.CH, 60, 0, "issue", "issuer.test")));
                CAADNSClient client = open(dns)) {
            assertReason(DNSLookupException.Reason.MALFORMED_RESPONSE, () -> client.resolveCaa(NAME, budget()));
        }
    }

    /**
     * Independently corrupt the question, type, opcode and transaction ID.
     * None of those responses may become a successful lookup.
     */
    @Test
    void missingQuestionsWrongTypesAndWrongOpcodesCannotProduceAResult() throws Exception {
        for (String variant : List.of("missing", "type", "opcode", "id")) {
            try (Fixture dns = new Fixture(query -> {
                Message response = reply(query, 0, caa(NAME.asciiAbsoluteName(), new byte[] { 'x' }));
                if (variant.equals("missing") || variant.equals("type")) {
                    response.removeAllRecords(Section.QUESTION);
                    if (variant.equals("type")) {
                        response.addRecord(Record.newRecord(name(NAME.asciiAbsoluteName()), Type.TXT, DClass.IN),
                                Section.QUESTION);
                    }
                }

                if (variant.equals("opcode")) {
                    response.getHeader().setOpcode(Opcode.UPDATE);
                }
                if (variant.equals("id")) {
                    response.getHeader().setID((query.getHeader().getID() + 1) & 65535);
                }

                return response;
            }); CAADNSClient client = open(dns)) {
                TestCAALookupBudget limited = new TestCAALookupBudget(
                    new CAAPolicy.Limits(Duration.ofSeconds(1), Duration.ofMillis(150), 2, 2, 1));
                assertThrows(DNSLookupException.class, () -> client.resolveCaa(NAME, limited), variant);
            }
        }
    }

    /**
     * Resolve several names concurrently through one client. Each result must
     * retain its own records and question evidence despite shared transport.
     */
    @Test
    void concurrentCallsCannotMixResponseOwnersOrEvidence() throws Exception {
        ExecutorService workers = Executors.newFixedThreadPool(4);
        try (Fixture dns = new Fixture(query -> reply(query, 0,
                caa(query.getQuestion().getName().toString(), new byte[] { 'x' }))); CAADNSClient client = open(dns)) {
            List<Future<CAADNSClient.LookupResult>> pending = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                DNSDomainName candidate = new DNSDomainName("n" + i + ".customer.test.");
                pending.add(workers.submit(() -> client.resolveCaa(candidate, budget())));
            }

            // Futures stay in submission order even if replies arrive out of order.
            // Check each record and observation against that caller's original name.
            for (int i = 0; i < pending.size(); i++) {
                DNSDomainName expected = new DNSDomainName("n" + i + ".customer.test.");
                CAADNSClient.LookupResult result = pending.get(i).get(3, TimeUnit.SECONDS);

                assertEquals(expected, result.candidate());
                assertEquals(expected, result.records().get(0).owner());
                assertEquals(expected, result.responses().get(0).question());
            }
        } finally {
            workers.shutdownNow();
        }
    }

    /**
     * Configures the real gate to load this fixture's adapter by class name.
     */
    private static Properties configuration(Fixture dns) {
        Properties properties = new Properties();
        properties.setProperty("enabled", "true");
        properties.setProperty("issuerIdentifiers", "issuer.test");
        properties.setProperty("dns.class", DNSJavaCAAProvider.class.getName());
        for (Map.Entry<String, String> setting : dns.config().settings().entrySet()) {
            properties.setProperty("dns.settings." + setting.getKey(), setting.getValue());
        }

        return properties;
    }

    private static CAADNSClient open(Fixture fixture) throws DNSLookupException {
        return new DNSJavaCAAProvider().open(fixture.config());
    }

    private static TestCAALookupBudget budget() {
        return new TestCAALookupBudget(
                new CAAPolicy.Limits(Duration.ofSeconds(3), Duration.ofSeconds(1), 10, 10, 2));
    }

    private static void assertReason(DNSLookupException.Reason expected, Action action) {
        DNSLookupException error = assertThrows(DNSLookupException.class, action::run);

        assertEquals(expected, error.failure().reason());
    }

    private interface Action {
        void run() throws Exception;
    }

    private static Name name(String value) {
        return Name.fromConstantString(value);
    }

    /**
     * Constructs issue RDATA directly so tests can supply arbitrary value bytes.
     * The first two octets contain flags and tag length, followed by "issue".
     */
    private static CAARecord caa(String owner, byte[] value) {
        byte[] rdata = new byte[7 + value.length];
        rdata[1] = 5;
        System.arraycopy(new byte[] { 'i', 's', 's', 'u', 'e' }, 0, rdata, 2, 5);
        System.arraycopy(value, 0, rdata, 7, value.length);

        return (CAARecord) Record.newRecord(name(owner), Type.CAA, DClass.IN, 60, rdata);
    }

    /**
     * Adds complete CAA records to a section for parsed response-limit tests.
     */
    private static void addCaaRecords(Message response, int section, int count) {
        for (int index = 0; index < count; index++) {
            String owner = "r" + section + "-" + index + ".test.";
            response.addRecord(caa(owner, new byte[] { 'x' }), section);
        }
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
        for (Record record : records) {
            response.addRecord(record, Section.ANSWER);
        }

        return response;
    }

    /**
     * Owns a loopback TCP listener and its worker sockets. The handler supplies
     * DNS messages; a null reply simulates a silent resolver. wireTransform can
     * corrupt serialized headers without requiring dnsjava to construct them.
     * close() stops workers and reports unexpected fixture failures to the test.
     */
    private static final class Fixture implements AutoCloseable {
        private final ServerSocket listener;
        private final Future<?> acceptor;
        private final ExecutorService workers = Executors.newCachedThreadPool(response -> {
            Thread thread = new Thread(response, "caa-dnsjava-fixture");
            thread.setDaemon(true);
            return thread;
        });
        private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
        private final AtomicReference<Throwable> failure = new AtomicReference<>();
        private final List<String> queries = new CopyOnWriteArrayList<>();

        Fixture(Function<Message, Message> handler) throws IOException {
            this(handler, UnaryOperator.identity());
        }

        Fixture(Function<Message, Message> handler, UnaryOperator<byte[]> wireTransform) throws IOException {
            listener = new ServerSocket(0, 16, InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 }));
            acceptor = workers.submit(() -> {
                while (!listener.isClosed()) {
                    try {
                        Socket socket = listener.accept();
                        sockets.add(socket);
                        workers.submit(() -> serve(socket, handler, wireTransform));
                    } catch (SocketException e) {
                        if (!listener.isClosed()) {
                            failure.compareAndSet(null, e);
                        }
                    } catch (IOException e) {
                        failure.compareAndSet(null, e);
                    }
                }
            });
        }

        private void serve(Socket socket, Function<Message, Message> handler, UnaryOperator<byte[]> wireTransform) {
            try (socket) {
                DataInputStream input = new DataInputStream(socket.getInputStream());
                DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                while (!listener.isClosed()) {
                    // TCP DNS frames start with a two-byte message length. Keep
                    // reading because dnsjava may reuse this socket for later queries.
                    int length = input.readUnsignedShort();
                    byte[] bytes = input.readNBytes(length);
                    Message query = new Message(bytes);
                    queries.add(query.getQuestion().getName().toString());
                    assertEquals(Type.CAA, query.getQuestion().getType());
                    // The handler controls the scenario. null keeps the connection
                    // open without replying, so the adapter must enforce its timeout.
                    Message response = handler.apply(query);
                    if (response != null) {
                        // Corrupt only after serialization when the test needs bytes
                        // that dnsjava would refuse to construct as a Message.
                        byte[] wire = wireTransform.apply(response.toWire());
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
            // Stop accepting before taking down sockets, so shutdown cannot leave
            // a newly accepted connection blocked in a fixture worker.
            acceptor.get(2, TimeUnit.SECONDS);
            for (Socket socket : sockets) {
                socket.close();
            }

            workers.shutdownNow();
            assertTrue(workers.awaitTermination(2, TimeUnit.SECONDS));
            // Worker exceptions otherwise stay on background threads and could make
            // a broken fixture look like the resolver timeout expected by a test.
            if (failure.get() != null) {
                throw new AssertionError("DNS fixture failed", failure.get());
            }
        }
    }
}
