// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later
package org.dogtagpki.acme.caa.libunbound;

import static org.junit.jupiter.api.Assertions.*;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.SocketException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import org.xbill.DNS.Message;

/** Shared TCP fixture for plugin tests; no external DNS infrastructure. */
final class NativeDnsServer implements AutoCloseable {
    private final ServerSocket socket;
    private final Thread worker;
    private final AtomicReference<Throwable> failure = new AtomicReference<>();
    final List<Message> queries = new CopyOnWriteArrayList<>();

    NativeDnsServer(Function<Message, byte[]> response) throws Exception {
        socket = new ServerSocket(0, 20, InetAddress.getByName("127.0.0.1"));
        worker = new Thread(() -> {
            try {
                while (!socket.isClosed()) {
                    try (var client = socket.accept()) {
                        client.setSoTimeout(2000);
                        var in = new DataInputStream(client.getInputStream());
                        int length = in.readUnsignedShort();
                        byte[] packet = in.readNBytes(length);
                        Message query = new Message(packet);
                        queries.add(query);
                        byte[] bytes = response.apply(query);
                        if (bytes == null) { Thread.sleep(250); continue; }
                        var out = new DataOutputStream(client.getOutputStream());
                        out.writeShort(bytes.length);
                        out.write(bytes);
                        out.flush();
                    } catch (java.io.EOFException | SocketException e) {
                        // Resolver cancellation/priming can close a connection
                        // before its query or reply completes. Keep serving.
                    }
                }
            } catch (SocketException e) {
                if (!socket.isClosed()) failure.set(e);
            } catch (Throwable e) { failure.set(e); }
        }, "libunbound-caa-fixture");
        worker.setDaemon(true);
        worker.start();
    }

    InetSocketAddress address() {
        return new InetSocketAddress(socket.getInetAddress(), socket.getLocalPort());
    }

    @Override
    public void close() throws Exception {
        socket.close();
        worker.join(3000);
        assertFalse(worker.isAlive(), "TCP fixture did not stop");
        assertNull(failure.get(), "TCP fixture failed");
    }
}
