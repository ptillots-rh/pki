// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later
package org.dogtagpki.acme.caa;

import static org.junit.jupiter.api.Assertions.*;

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
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.xbill.DNS.CAARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Section;

/** Same failure/recovery workload for both production plugins, without public DNS. */
@Timeout(60)
public class CAAOperationalTest {
    private static final DNSDomainName NAME = new DNSDomainName("load.caaunit.");
    private static final CAARequest REQUEST = new CAARequest("operational",
            List.of(new CAARequest.CertificateName(NAME, false)), Map.of());
    private static final List<String> PROVIDERS = List.of(
            "org.dogtagpki.acme.caa.dnsjava.DNSJavaCAAProvider",
            "org.dogtagpki.acme.caa.libunbound.LibUnboundCAAProvider");

    @Test void repeatedTimeoutsReleaseResourcesAndHealthyDnsRecovers() throws Exception {
        for (String provider : PROVIDERS) {
            try (var dns = new FaultServer(); var client = open(provider, dns)) {
                client.resolveCaa(NAME, budget()); // Warm up shared library/transport state.
                long descriptors = descriptorCount();
                long nativeThreads = nativeThreadCount();
                int threads = Thread.getAllStackTraces().size();
                dns.silent.set(true);
                long started = System.nanoTime();
                for (int i = 0; i < 24; i++) {
                    var failure = assertThrows(DNSLookupException.class, () -> client.resolveCaa(NAME, budget()));
                    assertEquals(DNSLookupException.Reason.TIMEOUT, failure.failure().reason(), provider);
                }
                long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
                assertTrue(elapsed < 15000, provider + " accumulated slow timeout/teardown: " + elapsed);
                dns.silent.set(false);
                assertEquals(CAADNSClient.LookupKind.RRSET, client.resolveCaa(NAME, budget()).kind(), provider);
                // Allow shared transport pools, but reject growth proportional to failed calls.
                long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
                while (System.nanoTime() < until && !withinResourceAllowance(descriptors, threads, nativeThreads)) Thread.sleep(50);
                assertTrue(withinResourceAllowance(descriptors, threads, nativeThreads), provider + " retained resources after recovery");
                System.out.printf("%s: 24 timeouts in %d ms; fd %d -> %d; Java threads %d -> %d; OS threads %d -> %d%n",
                        provider, elapsed, descriptors, descriptorCount(), threads, Thread.getAllStackTraces().size(),
                        nativeThreads, nativeThreadCount());
            }
        }
    }

    @Test void saturationRejectsExcessWorkAndReleasesAdmissionSlots() throws Exception {
        for (String provider : PROVIDERS) {
            var workers = Executors.newFixedThreadPool(8);
            try (var dns = new FaultServer(); var validator = new DefaultCAAValidator(open(provider, dns),
                    new CAAPolicy(Set.of("ca.example")))) {
                dns.hold = new CountDownLatch(1);
                dns.received = new CountDownLatch(8);
                var admitted = new ArrayList<Future<CAADecision>>();
                try {
                    for (int i = 0; i < 8; i++) admitted.add(workers.submit(() -> validator.validate(REQUEST)));
                    assertTrue(dns.received.await(800, TimeUnit.MILLISECONDS), provider + " did not admit eight checks");
                    for (int i = 0; i < 16; i++) {
                        var rejected = validator.validate(REQUEST);
                        assertEquals(CAADecision.Outcome.ERROR, rejected.outcome());
                        assertEquals(DNSLookupException.Reason.LIMIT_EXCEEDED,
                                rejected.names().get(0).failure().orElseThrow().reason());
                    }
                } finally { dns.hold.countDown(); }
                for (var check : admitted) assertEquals(CAADecision.Outcome.ALLOW, check.get(3, TimeUnit.SECONDS).outcome());
                assertEquals(CAADecision.Outcome.ALLOW, validator.validate(REQUEST).outcome(), provider);
            } finally { workers.shutdownNow(); assertTrue(workers.awaitTermination(3, TimeUnit.SECONDS)); }
        }
    }

    @Test void closingClientCancelsAllActiveCallsAndFreshClientRecovers() throws Exception {
        for (String provider : PROVIDERS) {
            var workers = Executors.newFixedThreadPool(8);
            try (var dns = new FaultServer(); var client = open(provider, dns)) {
                dns.silent.set(true);
                dns.received = new CountDownLatch(8);
                var active = new ArrayList<Future<DNSLookupException.Reason>>();
                for (int i = 0; i < 8; i++) active.add(workers.submit(() -> {
                    try { client.resolveCaa(NAME, longBudget()); return null; }
                    catch (DNSLookupException e) { return e.failure().reason(); }
                }));
                assertTrue(dns.received.await(3, TimeUnit.SECONDS));
                long started = System.nanoTime();
                client.close();
                for (var call : active) assertEquals(DNSLookupException.Reason.CANCELLED, call.get(3, TimeUnit.SECONDS), provider);
                assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(3), provider);
                dns.silent.set(false);
                try (var fresh = open(provider, dns)) {
                    assertEquals(CAADNSClient.LookupKind.RRSET, fresh.resolveCaa(NAME, budget()).kind());
                }
            } finally { workers.shutdownNow(); assertTrue(workers.awaitTermination(3, TimeUnit.SECONDS)); }
        }
    }

    @Test void interruptionStopsLookupWithoutPoisoningSubsequentChecks() throws Exception {
        for (String provider : PROVIDERS) {
            try (var dns = new FaultServer(); var client = open(provider, dns)) {
                dns.silent.set(true); dns.received = new CountDownLatch(1);
                var failure = new AtomicReference<Throwable>();
                Thread caller = new Thread(() -> {
                    try { client.resolveCaa(NAME, longBudget()); failure.set(new AssertionError("Interrupted lookup succeeded")); }
                    catch (DNSLookupException e) {
                        if (e.failure().reason() != DNSLookupException.Reason.CANCELLED)
                            failure.set(new AssertionError(e.failure().reason()));
                    } catch (Throwable e) { failure.set(e); }
                }, "caa-interrupted-caller");
                caller.start();
                try {
                    assertTrue(dns.received.await(3, TimeUnit.SECONDS));
                    caller.interrupt(); caller.join(3000);
                    assertFalse(caller.isAlive(), provider + " ignored interruption");
                    assertNull(failure.get(), provider);
                } finally { caller.interrupt(); caller.join(3000); }
                dns.silent.set(false);
                assertEquals(CAADNSClient.LookupKind.RRSET, client.resolveCaa(NAME, budget()).kind());
            }
        }
    }

    private static CAADNSClient open(String provider, FaultServer dns) throws DNSLookupException {
        return CAADNSClientLoader.open(provider, CAAOperationalTest.class.getClassLoader(),
                new CAADNSClientProvider.Config(Map.of("server", "127.0.0.1", "port", "" + dns.listener.getLocalPort())));
    }

    private static TestCAALookupBudget budget() {
        return new TestCAALookupBudget(new CAAPolicy.Limits(Duration.ofSeconds(1), Duration.ofMillis(150), 128, 16, 8));
    }
    private static TestCAALookupBudget longBudget() {
        return new TestCAALookupBudget(new CAAPolicy.Limits(Duration.ofSeconds(10), Duration.ofSeconds(10), 128, 16, 8));
    }
    private static long descriptorCount() throws Exception {
        if (!Files.isDirectory(Path.of("/proc/self/fd"))) return -1;
        try (var files = Files.list(Path.of("/proc/self/fd"))) { return files.count(); }
    }
    private static long nativeThreadCount() throws Exception {
        if (!Files.isDirectory(Path.of("/proc/self/task"))) return -1;
        try (var tasks = Files.list(Path.of("/proc/self/task"))) { return tasks.count(); }
    }
    private static boolean withinResourceAllowance(long descriptors, int threads, long nativeThreads) throws Exception {
        return (descriptors < 0 || descriptorCount() <= descriptors + 8)
                && Thread.getAllStackTraces().size() <= threads + 8
                && (nativeThreads < 0 || nativeThreadCount() <= nativeThreads + 8);
    }

    /** Real TCP impairment server. Quiet sockets stay open until the client cancels. */
    private static final class FaultServer implements AutoCloseable {
        final ServerSocket listener = new ServerSocket(0, 32, InetAddress.getByName("127.0.0.1"));
        final AtomicBoolean silent = new AtomicBoolean();
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
                        Socket socket = listener.accept(); sockets.add(socket);
                        workers.submit(() -> serve(socket));
                    } catch (SocketException e) { if (!listener.isClosed()) failure.set(e); }
                    catch (Exception e) { failure.set(e); }
                }
            }, "caa-fault-server");
            acceptor.setDaemon(true); acceptor.start();
        }

        private void serve(Socket socket) {
            try (socket) {
                var input = new DataInputStream(socket.getInputStream());
                var output = new DataOutputStream(socket.getOutputStream());
                while (!listener.isClosed()) {
                    Message query = new Message(input.readNBytes(input.readUnsignedShort()));
                    received.countDown();
                    // Read all multiplexed TCP queries even while replies are held.
                    workers.submit(() -> respond(query, output));
                }
            } catch (EOFException | SocketException e) {
                // Normal client cancellation and shutdown.
            } catch (Throwable e) { if (!listener.isClosed()) failure.compareAndSet(null, e); }
            finally { sockets.remove(socket); }
        }

        private void respond(Message query, DataOutputStream output) {
            try {
                hold.await(3, TimeUnit.SECONDS);
                if (silent.get()) return;
                Message answer = new Message(query.getHeader().getID());
                answer.getHeader().setFlag(Flags.QR); answer.getHeader().setFlag(Flags.RA);
                answer.addRecord(query.getQuestion(), Section.QUESTION);
                answer.addRecord(new CAARecord(query.getQuestion().getName(), DClass.IN, 60, 0, "issue", "ca.example"), Section.ANSWER);
                byte[] wire = answer.toWire();
                synchronized (output) { output.writeShort(wire.length); output.write(wire); output.flush(); }
            } catch (SocketException e) {
                // Cancellation can close a socket before a held reply is released.
            } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            catch (Throwable e) { if (!listener.isClosed()) failure.compareAndSet(null, e); }
        }

        @Override public void close() throws Exception {
            hold.countDown(); listener.close();
            for (Socket socket : sockets) socket.close();
            workers.shutdownNow(); acceptor.join(3000);
            assertFalse(acceptor.isAlive()); assertTrue(workers.awaitTermination(3, TimeUnit.SECONDS));
            assertNull(failure.get(), "Fault server failed");
        }
    }
}
