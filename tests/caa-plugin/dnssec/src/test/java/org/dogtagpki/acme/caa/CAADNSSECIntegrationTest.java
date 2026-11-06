// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedFlags;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

/** Private-root DNSSEC through delegated dnsjava and both in-process validators. */
@Timeout(60)
public class CAADNSSECIntegrationTest {
    private static final CAARequest REQUEST = new CAARequest("ci-dnssec",
            List.of(new CAARequest.CertificateName(new DNSDomainName("pki.example.com."), false)), Map.of());

    @Test void secureGrantReachesIssuer() throws Exception { exercise("secure-allow", CAADecision.Outcome.ALLOW); }
    @Test void secureDenialSuppressesIssuer() throws Exception { exercise("secure-deny", CAADecision.Outcome.DENY); }
    @Test void corruptedSignatureSuppressesIssuer() throws Exception { exercise("bogus", CAADecision.Outcome.ERROR); }
    @Test void authenticatedInsecurityCanAuthorize() throws Exception { exercise("insecure", CAADecision.Outcome.ALLOW); }
    @Test void signedAliasAbsenceUsesOriginalParent() throws Exception { exercise("alias-negative", CAADecision.Outcome.ALLOW); }
    @Test void resolverOutageSuppressesIssuer() throws Exception { exercise("outage", CAADecision.Outcome.ERROR); }

    @Test
    void wrongLocalRootAnchorCannotAuthorizeSignedOrUnsignedData() throws Exception {
        for (String scenario : List.of("secure-allow", "insecure")) {
            try (Fixture fixture = Fixture.start(scenario)) {
                Path anchors = fixture.directory.resolve("wrong-root.ds");
                Files.writeString(anchors, ". IN DS 12345 13 2 " + "00".repeat(32) + "\n");
                var submissions = new AtomicInteger();
                var audit = new AtomicReference<CAADecision>();
                try (var gate = CAAIssuanceGate.open(localConfig(anchors), getClass().getClassLoader())) {
                    assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                            () -> gate.issue(REQUEST, audit::set, submissions::incrementAndGet));
                }
                assertEquals(0, submissions.get());
                assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE,
                        audit.get().names().get(0).failure().orElseThrow().reason());
            }
        }
    }

    @Test
    void staticDnskeyAnchorIsSnapshottedAndValidatesLocally() throws Exception {
        try (Fixture fixture = Fixture.start("secure-allow")) {
            String keyName = Files.readString(fixture.directory.resolve("keys/root.name")).strip();
            Path anchors = fixture.directory.resolve("static-root.key");
            Files.copy(fixture.directory.resolve("keys").resolve(keyName + ".key"), anchors);
            var audit = new AtomicReference<CAADecision>();
            try (var gate = CAAIssuanceGate.open(localConfig(anchors), getClass().getClassLoader())) {
                Files.delete(anchors);
                assertEquals(1, gate.issue(REQUEST, audit::set, () -> 1));
            }
            for (var lookup : audit.get().names().get(0).discovery()) {
                for (var response : lookup.responses()) {
                    assertEquals(CAADNSClient.DNSSECStatus.SECURE, response.validationStatus());
                    assertEquals(CAADNSClient.ValidationAssurance.LOCAL_VALIDATOR, response.assurance());
                }
            }
        }
    }

    private static Properties localConfig(Path anchors) {
        Properties config = new Properties();
        config.setProperty("enabled", "true");
        config.setProperty("issuerIdentifiers", "ca.example.com");
        config.setProperty("dns.class", "org.dogtagpki.acme.caa.dnsjava.DNSJavaCAAProvider$Validating");
        config.setProperty("dns.settings.server", "127.0.0.1");
        config.setProperty("dns.settings.port", "1054");
        config.setProperty("dns.settings.trustAnchors", anchors.toString());
        return config;
    }

    private void exercise(String scenario, CAADecision.Outcome expected) throws Exception {
        try (Fixture fixture = Fixture.start(scenario)) {
            if (scenario.equals("outage")) fixture.close();
            for (String provider : List.of("delegated", "dnsjava-local", "libunbound")) {
                boolean nativePlugin = provider.equals("libunbound");
                boolean local = !provider.equals("delegated");
                Properties config = new Properties();
                config.setProperty("enabled", "true");
                config.setProperty("issuerIdentifiers", "ca.example.com");
                config.setProperty("dns.class", nativePlugin
                        ? "org.dogtagpki.acme.caa.libunbound.LibUnboundCAAProvider$Validating"
                        : "org.dogtagpki.acme.caa.dnsjava.DNSJavaCAAProvider$"
                                + (local ? "Validating" : "LocalValidatingResolver"));
                config.setProperty("dns.settings.server", "127.0.0.1");
                // In-process validators query the authority; delegation queries Unbound.
                config.setProperty("dns.settings.port", local ? "1054" : "1053");
                if (local) config.setProperty("dns.settings.trustAnchors", fixture.directory.resolve("root.ds").toString());
                var submissions = new AtomicInteger();
                var audit = new AtomicReference<CAADecision>();
                try (var gate = CAAIssuanceGate.open(config, getClass().getClassLoader())) {
                    if (expected == CAADecision.Outcome.ALLOW) {
                        assertEquals(1, gate.issue(REQUEST, audit::set, submissions::incrementAndGet));
                    } else {
                        assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                                () -> gate.issue(REQUEST, audit::set, submissions::incrementAndGet));
                    }
                }
                String context = scenario + " / " + provider;
                assertNotNull(audit.get(), context);
                assertEquals(expected, audit.get().outcome(), context);
                assertEquals(expected == CAADecision.Outcome.ALLOW ? 1 : 0, submissions.get(), context);
                var decision = audit.get().names().get(0);
                if (expected == CAADecision.Outcome.ERROR) {
                    assertEquals(CAADecision.Reason.DNS_FAILURE, decision.reason(), context);
                    if (scenario.equals("bogus")) {
                        // A dead fixture or timeout must not masquerade as successful DNSSEC testing.
                        assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE,
                                decision.failure().orElseThrow().reason(), context);
                    }
                } else {
                    var status = scenario.equals("insecure")
                            ? (local ? CAADNSClient.DNSSECStatus.PROVEN_INSECURE : CAADNSClient.DNSSECStatus.UNCLASSIFIED)
                            : CAADNSClient.DNSSECStatus.SECURE;
                    for (var lookup : decision.discovery()) {
                        for (var response : lookup.responses()) {
                            var expectedStatus = response.question().asciiAbsoluteName().equals(".")
                                    ? CAADNSClient.DNSSECStatus.SECURE : status;
                            assertEquals(expectedStatus, response.validationStatus(), context);
                        }
                        for (var record : lookup.records()) assertTrue(record.ttlSeconds() > 0, context);
                    }
                    if (scenario.equals("alias-negative")) {
                        assertFalse(decision.discovery().get(0).aliases().isEmpty(), context);
                        assertTrue(decision.discovery().get(0).negativeEvidence().isPresent(), context);
                        assertEquals(new DNSDomainName("example.com."), decision.relevantOwner().orElseThrow(), context);
                    }
                }
                System.out.println(context + ": " + expected);
            }
        }
    }

    /** Owns only test daemons on high loopback ports; system DNS and trust are untouched. */
    private static final class Fixture implements AutoCloseable {
        private final Path directory;
        private final List<Process> children = new ArrayList<>();

        private Fixture(Path directory) { this.directory = directory; }

        static Fixture start(String scenario) throws Exception {
            Path base = Path.of(System.getProperty("caa.fixture.directory"));
            Files.createDirectories(base);
            var fixture = new Fixture(Files.createTempDirectory(base, scenario + "-"));
            try {
                var generator = new ProcessBuilder("python3", System.getProperty("caa.fixture.generator"),
                        "--directory", fixture.directory.toString(), "--scenario",
                        scenario.equals("outage") ? "secure-allow" : scenario)
                        .redirectErrorStream(true).redirectOutput(fixture.directory.resolve("generate.log").toFile()).start();
                fixture.children.add(generator);
                assertTrue(generator.waitFor(20, TimeUnit.SECONDS), "DNSSEC fixture generation timed out");
                assertEquals(0, generator.exitValue(), "See " + fixture.directory.resolve("generate.log"));
                fixture.startDaemon("named", "-g", "-n", "1", "-U", "1", "-c", fixture.directory.resolve("named.conf").toString());
                fixture.startDaemon("unbound", "-d", "-c", fixture.directory.resolve("unbound.conf").toString());
                fixture.awaitValidatedRoot();
                return fixture;
            } catch (Exception | AssertionError e) {
                fixture.close();
                throw e;
            }
        }

        private void startDaemon(String... command) throws Exception {
            children.add(new ProcessBuilder(command).redirectErrorStream(true)
                    .redirectOutput(directory.resolve(command[0] + ".log").toFile()).start());
        }

        private void awaitValidatedRoot() throws Exception {
            var resolver = new SimpleResolver("127.0.0.1");
            resolver.setPort(1053);
            resolver.setTCP(true);
            resolver.setTimeout(Duration.ofMillis(200));
            resolver.setEDNS(0, 1232, ExtendedFlags.DO);
            Message query = Message.newQuery(Record.newRecord(Name.root, Type.DNSKEY, DClass.IN));
            query.getHeader().setFlag(Flags.AD);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
            while (System.nanoTime() < deadline) {
                assertTrue(children.get(1).isAlive() && children.get(2).isAlive(), "DNS server stopped; see " + directory);
                try {
                    Message response = resolver.send(query);
                    if (response.getRcode() == Rcode.NOERROR && response.getHeader().getFlag(Flags.AD)) return;
                } catch (java.io.IOException e) {
                    // Startup can precede socket binding. The root must validate before any assertion.
                }
                Thread.sleep(100);
            }
            fail("Private root never validated; see " + directory);
        }

        @Override public void close() throws InterruptedException {
            // Stop the resolver before its authority and bound every cleanup wait.
            for (int i = children.size() - 1; i >= 0; i--) {
                Process child = children.get(i);
                child.destroy();
                if (!child.waitFor(2, TimeUnit.SECONDS)) {
                    child.destroyForcibly();
                    assertTrue(child.waitFor(2, TimeUnit.SECONDS), "Cannot stop fixture process " + child.pid());
                }
            }
        }
    }
}
