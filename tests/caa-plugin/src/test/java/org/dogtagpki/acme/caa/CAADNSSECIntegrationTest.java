// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

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
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedFlags;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

/**
 * Private-root DNSSEC through the delegated dnsjava provider.
 *
 * - BIND serves the private signed hierarchy; Unbound validates it.
 * - Readiness requires a validated root answer, not just an open socket.
 * - Bogus data must produce a validation failure; a timeout is not a pass.
 * - Submission uses a recording callback, not an installed CA.
 * - Fixture processes and keys are private to this test run.
 * - Explicit opt-in requires -Dcaa.test.dnssec=true and installed DNS tools.
 */
@Timeout(60)
@EnabledIfSystemProperty(named = "caa.test.dnssec", matches = "true")
public class CAADNSSECIntegrationTest {
    private static final CAARequest REQUEST = new CAARequest(
            List.of(new CAARequest.CertificateName(new DNSDomainName("pki.example.com."), false)), Map.of());

    /**
     * Publish a correctly signed grant for this issuer. Real DNSSEC validation
     * and CAA policy evaluation must allow the recording submission callback.
     */
    @Test
    void secureGrantReachesIssuer() throws Exception {
        exercise("secure-allow", CAADecision.Outcome.ALLOW);
    }

    /**
     * Publish a correctly signed grant for another issuer. DNSSEC succeeds,
     * but CAA policy must deny and suppress the submission callback.
     */
    @Test
    void secureDenialSuppressesIssuer() throws Exception {
        exercise("secure-deny", CAADecision.Outcome.DENY);
    }

    /**
     * Change a restrictive CAA grant after signing it. Unbound must report
     * validation failure; neither a timeout nor policy denial counts as a pass.
     */
    @Test
    void corruptedSignatureSuppressesIssuer() throws Exception {
        exercise("bogus", CAADecision.Outcome.ERROR);
    }

    /**
     * Omit the child DS from the signed parent. Accept the unsigned child
     * through authenticated insecurity rather than requiring AD on every reply.
     */
    @Test
    void authenticatedInsecurityCanAuthorize() throws Exception {
        exercise("insecure", CAADecision.Outcome.ALLOW);
    }

    /**
     * Follow a signed alias to absence. The original parent grants while
     * the target parent denies, exposing incorrect parent-discovery behavior.
     */
    @Test
    void signedAliasAbsenceUsesOriginalParent() throws Exception {
        exercise("alias-negative", CAADecision.Outcome.ALLOW);
    }

    /**
     * Start and validate the fixture, then stop it before checking CAA.
     * Resolver unavailability must prevent the submission callback.
     */
    @Test
    void resolverOutageSuppressesIssuer() throws Exception {
        exercise("outage", CAADecision.Outcome.ERROR);
    }

    /**
     * Runs one signed-DNS scenario through the real gate, records submission,
     * and checks both the aggregate decision and the DNS evidence behind it.
     */
    private void exercise(String scenario, CAADecision.Outcome expected) throws Exception {
        try (Fixture fixture = Fixture.start(scenario)) {
            if (scenario.equals("outage")) {
                fixture.close();
            }

            Properties config = new Properties();
            config.setProperty("enabled", "true");
            config.setProperty("issuerIdentifiers", "ca.example.com");
            config.setProperty("dns.class",
                    "org.dogtagpki.acme.caa.dnsjava.DNSJavaCAAProvider");
            config.setProperty("dns.settings.server", "127.0.0.1");
            config.setProperty("dns.settings.port", "1053");
            // Capture the decision independently of submission: denied and failed
            // checks still produce evidence, but must never call the recording issuer.
            AtomicInteger submissions = new AtomicInteger();
            AtomicReference<CAADecision> observedDecision = new AtomicReference<>();

            try (CAAIssuanceGate gate = CAAIssuanceGate.open(config, getClass().getClassLoader())) {
                if (expected == CAADecision.Outcome.ALLOW) {
                    int submitted = TestCAAIssuance.submit(gate, REQUEST,
                            observedDecision::set, submissions::incrementAndGet);
                    assertEquals(1, submitted);
                } else {
                    assertThrows(CAAIssuanceGate.CAAApprovalException.class,
                            () -> TestCAAIssuance.submit(gate, REQUEST,
                                    observedDecision::set, submissions::incrementAndGet));
                }
            }

            String context = scenario + " / delegated dnsjava";
            assertNotNull(observedDecision.get(), context);
            assertEquals(expected, observedDecision.get().outcome(), context);
            assertEquals(expected == CAADecision.Outcome.ALLOW ? 1 : 0, submissions.get(), context);
            CAADecision.NameDecision decision = observedDecision.get().names().get(0);

            if (expected == CAADecision.Outcome.ERROR) {
                assertEquals(CAADecision.Reason.DNS_FAILURE, decision.reason(), context);
                if (scenario.equals("bogus")) {
                    // A dead fixture or timeout must not masquerade as successful DNSSEC testing.
                    assertEquals(DNSLookupException.Reason.VALIDATION_FAILURE,
                            decision.failure().orElseThrow().reason(), context);
                }
            } else {
                assertDiscovery(scenario, decision, context);
            }

            System.out.println(context + ": " + expected);
        }
    }

    /**
     * Checks DNSSEC classifications and the original-parent rule independently
     * of the submission assertions. A policy denial can still have secure DNS.
     */
    private static void assertDiscovery(String scenario, CAADecision.NameDecision decision, String context) {
        CAADNSClient.ValidationStatus status = scenario.equals("insecure")
                ? CAADNSClient.ValidationStatus.UNCLASSIFIED
                : CAADNSClient.ValidationStatus.SECURE;
        // Inspect every exchange, including aliases and parent discovery,
        // rather than accepting an aggregate ALLOW or DENY as proof of validation.
        for (CAADNSClient.LookupResult lookup : decision.discovery()) {
            for (CAADNSClient.ResponseEvidence response : lookup.responses()) {
                assertEquals(status, response.validationStatus(), context);
            }

            for (CAADNSClient.CAARecord record : lookup.records()) {
                assertTrue(record.ttlSeconds() > 0, context);
            }
        }

        // The target has no CAA and its parent denies. Success therefore requires
        // returning to the original name's parent, which carries the valid grant.
        if (scenario.equals("alias-negative")) {
            assertFalse(decision.discovery().get(0).aliases().isEmpty(), context);
            assertTrue(decision.discovery().get(0).negativeSoa().isPresent(), context);
            assertEquals(new DNSDomainName("target.branch.example.com."),
                    decision.discovery().get(0).terminalName(), context);
            assertEquals(new DNSDomainName("example.com."),
                    decision.discovery().get(1).candidate(), context);
            assertEquals(new DNSDomainName("example.com."), decision.relevantOwner().orElseThrow(), context);
        }
    }

    /**
     * Owns only test daemons on high loopback ports; system DNS and trust are untouched.
     */
    private static final class Fixture implements AutoCloseable {
        private final Path directory;
        private final List<Process> children = new ArrayList<>();

        private Fixture(Path directory) {
            this.directory = directory;
        }

        /**
         * Generates private zones, starts authority and resolver, then waits for
         * a validated root answer. Failed setup closes any processes already started.
         */
        static Fixture start(String scenario) throws Exception {
            Path base = Path.of(System.getProperty("caa.fixture.directory"));
            Files.createDirectories(base);
            Fixture fixture = new Fixture(Files.createTempDirectory(base, scenario + "-"));
            try {
                // Outage starts from a healthy signed hierarchy. The test stops it
                // only after readiness, so setup failure cannot count as its result.
                String zoneScenario = scenario.equals("outage") ? "secure-allow" : scenario;
                ProcessBuilder generation = new ProcessBuilder("python3", System.getProperty("caa.fixture.generator"),
                        "--directory", fixture.directory.toString(), "--scenario", zoneScenario);
                generation.redirectErrorStream(true);
                generation.redirectOutput(fixture.directory.resolve("generate.log").toFile());
                Process generator = generation.start();
                // Track each process as soon as it starts so partial setup failures
                // are cleaned up by the same lifecycle as a completed fixture.
                fixture.children.add(generator);
                assertTrue(generator.waitFor(20, TimeUnit.SECONDS), "DNSSEC fixture generation timed out");
                assertEquals(0, generator.exitValue(), "See " + fixture.directory.resolve("generate.log"));
                // Generate all keys and zone files before either daemon reads them.
                // The authority starts first; readiness waits for actual validation.
                fixture.startDaemon("named", "-g", "-n", "1", "-U", "1", "-c",
                        fixture.directory.resolve("named.conf").toString());
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

        /**
         * An open TCP port does not prove readiness. Require an AD-set root
         * DNSKEY response from the private hierarchy before exercising CAA.
         */
        private void awaitValidatedRoot() throws Exception {
            SimpleResolver resolver = new SimpleResolver("127.0.0.1");
            resolver.setPort(1053);
            resolver.setTCP(true);
            resolver.setTimeout(Duration.ofMillis(200));
            resolver.setEDNS(0, 1232, ExtendedFlags.DO);
            Message query = Message.newQuery(Record.newRecord(Name.root, Type.DNSKEY, DClass.IN));
            query.getHeader().setFlag(Flags.AD);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
            while (System.nanoTime() < deadline) {
                // The generator is children[0]; BIND and Unbound follow it.
                assertTrue(children.get(1).isAlive() && children.get(2).isAlive(),
                        "DNS server stopped; see " + directory);
                try {
                    // Query the private root through Unbound, rather than BIND
                    // directly, to exercise the resolver and its configured anchor.
                    Message response = resolver.send(query);
                    if (response.getRcode() == Rcode.NOERROR && response.getHeader().getFlag(Flags.AD)) {
                        return;
                    }
                } catch (java.io.IOException e) {
                    // Startup can precede socket binding. The root must validate before any assertion.
                }

                Thread.sleep(100);
            }

            fail("Private root never validated; see " + directory);
        }

        @Override
        public void close() throws InterruptedException {
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
