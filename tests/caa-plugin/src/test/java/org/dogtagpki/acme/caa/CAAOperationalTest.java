// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
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
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.xbill.DNS.CAARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Section;

/**
 * Tests whether the shared CAA validator and dnsjava transport remain bounded
 * under timeouts, saturation, cancellation and shutdown. A local TCP server
 * holds or suppresses replies so each workload controls when work can finish.
 *
 * These tests use real threads and sockets but no DNSSEC daemons or public DNS.
 * They complement policy unit tests by checking resource ownership and recovery;
 * they are not throughput benchmarks or production load qualification.
 */
@Timeout(60)
public class CAAOperationalTest {
    private static final DNSDomainName NAME = new DNSDomainName("load.caaunit.");
    private static final CAARequest REQUEST = new CAARequest(List.of(new CAARequest.CertificateName(NAME, false)), Map.of());
    private static final String PROVIDER = "org.dogtagpki.acme.caa.dnsjava.DNSJavaCAAProvider";

    /**
     * Suppress 24 replies, then restore service. Query timeouts must remain
     * bounded and shared transport resources must settle after recovery.
     */
    @Test
    void repeatedTimeoutsReleaseResourcesAndHealthyDnsRecovers() throws Exception {
        try (FaultServer dns = new FaultServer(); CAADNSClient client = open(PROVIDER, dns)) {
            // Complete one query before measuring shared library/transport state.
            client.resolveCaa(NAME, budget());
            long descriptors = descriptorCount();
            long nativeThreads = nativeThreadCount();
            int threads = Thread.getAllStackTraces().size();
            dns.silent.set(true);
            long started = System.nanoTime();

            // Reuse one client across enough failures to expose per-query leaks.
            // Each call must end as TIMEOUT, rather than eventually hitting capacity.
            for (int i = 0; i < 24; i++) {
                DNSLookupException failure = assertThrows(DNSLookupException.class, () -> client.resolveCaa(NAME, budget()));
                assertEquals(DNSLookupException.Reason.TIMEOUT, failure.failure().reason(), PROVIDER);
            }

            long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
            assertTrue(elapsed < 15000, PROVIDER + " accumulated slow timeout/teardown: " + elapsed);
            dns.silent.set(false);
            assertEquals(CAADNSClient.LookupKind.RRSET, client.resolveCaa(NAME, budget()).kind(), PROVIDER);
            // Allow shared transport pools, but reject growth proportional to failed calls.
            long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
            while (System.nanoTime() < until
                    && !withinResourceAllowance(descriptors, threads, nativeThreads)) {
                Thread.sleep(50);
            }
            assertTrue(withinResourceAllowance(descriptors, threads, nativeThreads),
                    PROVIDER + " retained resources after recovery");
            System.out.printf("%s: 24 timeouts in %d ms; fd %d -> %d; Java threads %d -> %d; OS threads %d -> %d%n",
                    PROVIDER, elapsed, descriptors, descriptorCount(), threads, Thread.getAllStackTraces().size(),
                    nativeThreads, nativeThreadCount());
        }
    }

    /**
     * Hold eight admitted validations at the DNS server. Additional attempts
     * must fail immediately; releasing the replies must restore admission.
     */
    @Test
    void saturationRejectsExcessWorkAndReleasesAdmissionSlots() throws Exception {
        ExecutorService workers = Executors.newFixedThreadPool(8);
        try (FaultServer dns = new FaultServer();
                DefaultCAAValidator validator = new DefaultCAAValidator(open(PROVIDER, dns),
                        new CAAPolicy(Set.of("ca.example")))) {
            // Keep all eight admitted checks active until excess work is rejected.
            dns.hold = new CountDownLatch(1);
            dns.received = new CountDownLatch(8);
            List<Future<CAADecision>> admitted = new ArrayList<>();
            try {
                for (int i = 0; i < 8; i++) {
                    admitted.add(workers.submit(() -> validator.validate(REQUEST)));
                }
                assertTrue(dns.received.await(800, TimeUnit.MILLISECONDS), PROVIDER + " did not admit eight checks");

                // All slots are still occupied because replies remain held.
                // Excess calls must return a capacity error rather than queue for DNS.
                for (int i = 0; i < 16; i++) {
                    CAADecision rejected = validator.validate(REQUEST);
                    assertEquals(CAADecision.Outcome.ERROR, rejected.outcome());
                    assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED,
                            rejected.names().get(0).failure().orElseThrow().reason());
                }
            } finally {
                dns.hold.countDown();
            }

            // Releasing replies must complete the admitted work successfully;
            // rejecting excess requests must not cancel those original validations.
            for (Future<CAADecision> check : admitted) {
                assertEquals(CAADecision.Outcome.ALLOW, check.get(3, TimeUnit.SECONDS).outcome());
            }

            assertEquals(CAADecision.Outcome.ALLOW, validator.validate(REQUEST).outcome(), PROVIDER);
        } finally {
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(3, TimeUnit.SECONDS));
        }
    }

    /**
     * Leave eight lookups waiting, close their client and check cancellation.
     * A new client must resolve successfully when the server responds again.
     */
    @Test
    void closingClientCancelsWaitingCallersAndFreshClientRecovers() throws Exception {
        ExecutorService workers = Executors.newFixedThreadPool(8);
        try (FaultServer dns = new FaultServer(); CAADNSClient client = open(PROVIDER, dns)) {
            dns.silent.set(true);
            dns.received = new CountDownLatch(8);
            List<Future<DNSLookupException.Reason>> active = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                active.add(workers.submit(() -> {
                    try {
                        client.resolveCaa(NAME, longBudget());
                        return null;
                    } catch (DNSLookupException e) {
                        return e.failure().reason();
                    }
                }));
            }
            // Wait for actual DNS traffic before close(), so the assertions
            // exercise active callers rather than tasks that never started.
            assertTrue(dns.received.await(3, TimeUnit.SECONDS));
            long started = System.nanoTime();
            client.close();
            for (Future<DNSLookupException.Reason> call : active) {
                assertEquals(DNSLookupException.Reason.CANCELLED, call.get(3, TimeUnit.SECONDS), PROVIDER);
            }

            assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(3), PROVIDER);
            dns.silent.set(false);
            try (CAADNSClient fresh = open(PROVIDER, dns)) {
                assertEquals(CAADNSClient.LookupKind.RRSET, fresh.resolveCaa(NAME, budget()).kind());
            }
        } finally {
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(3, TimeUnit.SECONDS));
        }
    }

    /**
     * Hold queries from two clients using dnsjava's shared transport. Closing
     * one client must cancel its caller without closing the other client's
     * active lookup or preventing subsequent use of that surviving client.
     */
    @Test
    void closingOneClientDoesNotCancelAnotherClientsActiveLookup() throws Exception {
        ExecutorService workers = Executors.newFixedThreadPool(2);
        try (FaultServer dns = new FaultServer();
                CAADNSClient closing = open(PROVIDER, dns);
                CAADNSClient surviving = open(PROVIDER, dns)) {
            dns.hold = new CountDownLatch(1);
            dns.received = new CountDownLatch(2);
            try {
                Future<DNSLookupException> cancelled = workers.submit(() ->
                        assertThrows(DNSLookupException.class, () -> closing.resolveCaa(NAME, longBudget())));
                Future<CAADNSClient.LookupResult> active = workers.submit(() ->
                        surviving.resolveCaa(NAME, longBudget()));
                assertTrue(dns.received.await(3, TimeUnit.SECONDS), "Both clients must have active queries");

                closing.close();
                DNSLookupException error = cancelled.get(3, TimeUnit.SECONDS);

                // Replies are still blocked. Only the explicitly closed client
                // should have completed; the surviving lookup must remain active.
                assertEquals(DNSLookupException.Reason.CANCELLED, error.failure().reason());
                assertFalse(active.isDone(), "The other client's query must remain pending while replies are held");

                dns.hold.countDown();
                CAADNSClient.LookupResult result = active.get(3, TimeUnit.SECONDS);

                assertEquals(CAADNSClient.LookupKind.RRSET, result.kind());
                assertEquals(NAME, result.terminalName());
                assertEquals(CAADNSClient.LookupKind.RRSET, surviving.resolveCaa(NAME, budget()).kind());
            } finally {
                dns.hold.countDown();
            }
        } finally {
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(3, TimeUnit.SECONDS));
        }
    }

    /**
     * Interrupt a caller after its query reaches the server. It must stop
     * with CANCELLED, while the shared client remains usable for later calls.
     */
    @Test
    void interruptionStopsLookupWithoutPoisoningSubsequentChecks() throws Exception {
        try (FaultServer dns = new FaultServer(); CAADNSClient client = open(PROVIDER, dns)) {
            dns.silent.set(true);
            dns.received = new CountDownLatch(1);
            AtomicReference<Throwable> failure = new AtomicReference<>();
            Thread caller = new Thread(() -> {
                try {
                    client.resolveCaa(NAME, longBudget());
                    failure.set(new AssertionError("Interrupted lookup succeeded"));
                } catch (DNSLookupException e) {
                    if (e.failure().reason() != DNSLookupException.Reason.CANCELLED) {
                        failure.set(new AssertionError(e.failure().reason()));
                    }
                } catch (Throwable e) {
                    failure.set(e);
                }
            }, "caa-interrupted-caller");
            caller.start();
            try {
                assertTrue(dns.received.await(3, TimeUnit.SECONDS));
                caller.interrupt();
                caller.join(3000);
                assertFalse(caller.isAlive(), PROVIDER + " ignored interruption");
                assertNull(failure.get(), PROVIDER);
            } finally {
                caller.interrupt();
                caller.join(3000);
            }

            dns.silent.set(false);
            assertEquals(CAADNSClient.LookupKind.RRSET, client.resolveCaa(NAME, budget()).kind());
        }
    }

    /**
     * Interrupt eight callers while their TCP replies remain held. Their
     * transport slots must stay occupied until the underlying queries finish;
     * otherwise repeated cancellation could accumulate unbounded network work.
     */
    @Test
    void cancelledCallersKeepTransportAdmissionUntilUnderlyingQueriesComplete() throws Exception {
        try (FaultServer dns = new FaultServer(); CAADNSClient client = open(PROVIDER, dns)) {
            dns.hold = new CountDownLatch(1);
            try {
                // Cancel each caller after its query reaches the fixture. Its TCP
                // reply remains held, so every iteration leaves one slot occupied.
                for (int i = 0; i < 8; i++) {
                    dns.received = new CountDownLatch(1);
                    AtomicReference<Throwable> error = new AtomicReference<>();
                    Thread caller = new Thread(() -> {
                        try {
                            client.resolveCaa(NAME, longBudget());
                            error.set(new AssertionError("Interrupted query succeeded"));
                        } catch (DNSLookupException e) {
                            if (e.failure().reason() != DNSLookupException.Reason.CANCELLED) {
                                error.set(e);
                            }
                        } catch (Throwable e) {
                            error.set(e);
                        }
                    });
                    caller.start();
                    try {
                        assertTrue(dns.received.await(2, TimeUnit.SECONDS));
                    } finally {
                        caller.interrupt();
                        caller.join(2000);
                    }

                    assertFalse(caller.isAlive());
                    assertNull(error.get());
                }

                // A ninth lookup must fail before reaching the server. Caller
                // cancellation alone must not create room for more pending TCP work.
                DNSLookupException refused = assertThrows(DNSLookupException.class,
                        () -> client.resolveCaa(NAME, longBudget()));
                assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED, refused.failure().reason());
                assertEquals(8, dns.queries.get(), "Cancellation must not release transport admission");
            } finally {
                dns.hold.countDown();
            }

            // Releasing held replies permits transport cleanup independently of callers.
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
            while (true) {
                try {
                    assertEquals(CAADNSClient.LookupKind.RRSET, client.resolveCaa(NAME, budget()).kind());
                    break;
                } catch (DNSLookupException e) {
                    // TCP completion is asynchronous. Only temporary capacity errors
                    // are acceptable while the released replies finish cleaning up.
                    assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED, e.failure().reason());
                    assertTrue(System.nanoTime() < deadline, "Completed transport did not release admission");
                    Thread.sleep(10);
                }
            }
        }
    }

    private static CAADNSClient open(String provider, FaultServer dns) throws DNSLookupException {
        Map<String, String> settings = Map.of(
                "server", "127.0.0.1", "port", Integer.toString(dns.listener.getLocalPort()));
        return CAADNSClientLoader.open(provider, CAAOperationalTest.class.getClassLoader(),
                new CAADNSClientProvider.Config(settings));
    }

    /**
     * Short query timeouts keep the repeated-outage workload bounded.
     */
    private static TestCAALookupBudget budget() {
        return new TestCAALookupBudget(new CAAPolicy.Limits(Duration.ofSeconds(1), Duration.ofMillis(150), 128, 16, 8));
    }

    /**
     * Keep timeout beyond the test's cancellation wait so CANCELLED, rather
     * than TIMEOUT, demonstrates that close() or interruption stopped the caller.
     */
    private static TestCAALookupBudget longBudget() {
        return new TestCAALookupBudget(new CAAPolicy.Limits(Duration.ofSeconds(10), Duration.ofSeconds(10), 128, 16, 8));
    }

    private static long descriptorCount() throws Exception {
        if (!Files.isDirectory(Path.of("/proc/self/fd"))) {
            return -1;
        }

        try (var files = Files.list(Path.of("/proc/self/fd"))) {
            return files.count();
        }
    }

    private static long nativeThreadCount() throws Exception {
        if (!Files.isDirectory(Path.of("/proc/self/task"))) {
            return -1;
        }

        try (var tasks = Files.list(Path.of("/proc/self/task"))) {
            return tasks.count();
        }
    }

    private static boolean withinResourceAllowance(long descriptors, int threads, long nativeThreads) throws Exception {
        return (descriptors < 0 || descriptorCount() <= descriptors + 8)
                && Thread.getAllStackTraces().size() <= threads + 8
                && (nativeThreads < 0 || nativeThreadCount() <= nativeThreads + 8);
    }

    /**
     * Controls reply timing independently of callers. received signals that a
     * query arrived, hold blocks replies, and silent discards them. Reader and
     * reply workers are separate because dnsjava can multiplex queries on TCP.
     * Pooled sockets may outlive cancelled callers; close() releases held work,
     * closes sockets and propagates unexpected worker failures.
     */
    private static final class FaultServer implements AutoCloseable {
        final ServerSocket listener = new ServerSocket(0, 32, InetAddress.getByName("127.0.0.1"));
        final AtomicBoolean silent = new AtomicBoolean();
        final AtomicInteger queries = new AtomicInteger();
        volatile CountDownLatch received = new CountDownLatch(0);
        volatile CountDownLatch hold = new CountDownLatch(0);
        private final ExecutorService workers = Executors.newCachedThreadPool();
        private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
        private final AtomicReference<Throwable> failure = new AtomicReference<>();
        private final Thread acceptor;

        FaultServer() throws Exception {
            acceptor = new Thread(() -> {
                while (!listener.isClosed()) {
                    try {
                        Socket socket = listener.accept();
                        sockets.add(socket);
                        workers.submit(() -> serve(socket));
                    } catch (SocketException e) {
                        if (!listener.isClosed()) {
                            failure.set(e);
                        }
                    } catch (Exception e) {
                        failure.set(e);
                    }
                }
            }, "caa-fault-server");
            acceptor.setDaemon(true);
            acceptor.start();
        }

        private void serve(Socket socket) {
            try (socket) {
                DataInputStream input = new DataInputStream(socket.getInputStream());
                DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                while (!listener.isClosed()) {
                    int length = input.readUnsignedShort();
                    byte[] wire = input.readNBytes(length);
                    Message query = new Message(wire);
                    // Signal receipt before dispatching the reply. Tests can then
                    // cancel callers knowing their TCP queries actually arrived.
                    queries.incrementAndGet();
                    received.countDown();

                    // Read all multiplexed TCP queries even while replies are held.
                    workers.submit(() -> respond(query, output));
                }
            } catch (EOFException | SocketException e) {
                // Normal client cancellation and shutdown.
            } catch (Throwable e) {
                if (!listener.isClosed()) {
                    failure.compareAndSet(null, e);
                }
            } finally {
                sockets.remove(socket);
            }
        }

        private void respond(Message query, DataOutputStream output) {
            try {
                // hold models delayed replies; silent models a resolver that never
                // answers. Bound the hold so a failed test cannot strand this worker.
                hold.await(10, TimeUnit.SECONDS);
                if (silent.get()) {
                    return;
                }

                Message answer = new Message(query.getHeader().getID());
                answer.getHeader().setFlag(Flags.QR);
                answer.getHeader().setFlag(Flags.RA);
                answer.addRecord(query.getQuestion(), Section.QUESTION);
                answer.addRecord(new CAARecord(query.getQuestion().getName(), DClass.IN,
                        60, 0, "issue", "ca.example"), Section.ANSWER);
                byte[] wire = answer.toWire();

                // Reply workers share a connection. Write each length and message
                // together so concurrent responses cannot interleave their TCP frames.
                synchronized (output) {
                    output.writeShort(wire.length);
                    output.write(wire);
                    output.flush();
                }
            } catch (SocketException e) {
                // Cancellation can close a socket before a held reply is released.
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Throwable e) {
                if (!listener.isClosed()) {
                    failure.compareAndSet(null, e);
                }
            }
        }

        @Override
        public void close() throws Exception {
            // Unblock delayed replies and socket readers before joining workers.
            // Interrupting a Java thread alone does not release a blocking socket read.
            hold.countDown();
            listener.close();
            for (Socket socket : sockets) {
                socket.close();
            }

            workers.shutdownNow();
            acceptor.join(3000);
            assertFalse(acceptor.isAlive());
            assertTrue(workers.awaitTermination(3, TimeUnit.SECONDS));
            assertNull(failure.get(), "Fault server failed");
        }
    }
}
