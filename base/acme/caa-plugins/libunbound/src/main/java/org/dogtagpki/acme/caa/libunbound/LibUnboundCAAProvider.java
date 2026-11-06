// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa.libunbound;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.dogtagpki.acme.caa.CAADNSClient;
import org.dogtagpki.acme.caa.CAADNSClientProvider;
import org.dogtagpki.acme.caa.DNSDomainName;
import org.dogtagpki.acme.caa.DNSLookupException;

/** Embedded libunbound resolution; no daemon, CLI, dnsjava or JNA dependency. */
public class LibUnboundCAAProvider implements CAADNSClientProvider {
    private static boolean loaded;

    @Override public CAADNSClient.ValidationMode validationMode() { return CAADNSClient.ValidationMode.UNCHECKED; }

    /** Fixed local validation behavior, requiring explicitly provisioned DNSSEC anchors. */
    public static final class Validating extends LibUnboundCAAProvider {
        @Override public CAADNSClient.ValidationMode validationMode() { return CAADNSClient.ValidationMode.LOCAL_ENFORCING; }
    }

    @Override public CAADNSClient open(Config config) throws DNSLookupException {
        try {
            if (!Set.of("server", "port", "trustAnchors").containsAll(config.settings().keySet())) {
                throw new IllegalArgumentException("Unknown native DNS setting");
            }
            String server = config.settings().getOrDefault("server", "");
            if (!server.matches("[0-9.]+") && !(server.contains(":") && server.matches("[0-9A-Fa-f:.]+"))) {
                throw new IllegalArgumentException("Numeric resolver address required");
            }
            int port = Integer.parseInt(config.settings().getOrDefault("port", "53"));
            if (port < 1 || port > 65535) throw new IllegalArgumentException("Invalid resolver port");
            var endpoint = new InetSocketAddress(InetAddress.getByName(server), port);
            boolean validating = validationMode() == CAADNSClient.ValidationMode.LOCAL_ENFORCING;
            String file = config.settings().get("trustAnchors");
            if (validating != (file != null)) throw new IllegalArgumentException("Anchors must match fixed provider behavior");
            Anchors anchors = validating ? readAnchors(Path.of(file)) : new Anchors(List.of(), false);
            loadLibrary();
            checkAnchorsNative(anchors.records().toArray(String[]::new));
            return new Client(endpoint, anchors, validationMode());
        } catch (IOException | RuntimeException | LinkageError e) {
            throw failure(DNSLookupException.Reason.CONFIGURATION, "Cannot initialize libunbound CAA provider", e);
        }
    }

    private static synchronized void loadLibrary() {
        if (!loaded) {
            System.loadLibrary("pki_acme_unbound");
            loaded = true;
        }
    }

    /** Explicit static records, snapshotted at startup. Rollover is owned by an external updater. */
    private static Anchors readAnchors(Path path) throws IOException {
        byte[] bytes;
        try (var input = Files.newInputStream(path)) { bytes = input.readNBytes(1024 * 1024 + 1); }
        if (bytes.length > 1024 * 1024) throw new IOException("Anchor file exceeds limit");
        for (byte b : bytes) {
            if (b < 0 || (b < 32 && b != '\n' && b != '\r' && b != '\t')) throw new IOException("Non-ASCII anchor file");
        }
        List<String> records = new ArrayList<>();
        boolean root = false;
        for (String line : new String(bytes, StandardCharsets.US_ASCII).split("\\R")) {
            // RFC 5011 state comments distinguish pending/revoked keys from
            // trusted keys. Stripping those comments would silently trust all
            // records in a managed file. Require an explicit static export.
            if (line.matches("(?i).*\\bstate\\s*=.*") || line.toLowerCase(java.util.Locale.ROOT).contains("autotrust trust anchor")) {
                throw new IOException("Managed anchor state requires a static export of trusted keys");
            }
            String record = line.split(";", 2)[0].strip();
            if (record.isEmpty()) continue;
            if (records.size() == 128 || record.length() > 8192
                    || !record.matches("(?i)\\S+\\s+(?:[0-9]+\\s+)?IN\\s+(?:DS|DNSKEY)\\s+[^()]+")) {
                throw new IOException("Expected explicit single-line IN DS/DNSKEY records");
            }
            String[] fields = record.split("\\s+", 2);
            validateAnchorFields(record);
            String owner = fields[0];
            if (!owner.endsWith(".")) owner += ".";
            owner = new DNSDomainName(owner).asciiAbsoluteName();
            root |= owner.equals(".");
            records.add(owner + " " + fields[1]);
        }
        if (records.isEmpty()) throw new IOException("Empty anchor file");
        return new Anchors(List.copyOf(records), root);
    }

    /** Validates the configured record format, not its cryptographic authenticity. */
    private static void validateAnchorFields(String record) throws IOException {
        try {
            String[] fields = record.split("\\s+");
            int type = fields[1].equalsIgnoreCase("IN") ? 2 : 3;
            int start = type + 1;
            if (fields.length < start + 4) throw new IllegalArgumentException("Short anchor record");
            int flagsOrTag = Integer.parseInt(fields[start]);
            int protocolOrAlgorithm = Integer.parseInt(fields[start + 1]);
            int algorithmOrDigest = Integer.parseInt(fields[start + 2]);
            if (flagsOrTag < 0 || flagsOrTag > 65535 || protocolOrAlgorithm < 0 || protocolOrAlgorithm > 255
                    || algorithmOrDigest < 1 || algorithmOrDigest > 255) throw new IllegalArgumentException("Anchor numeric field");
            String data = String.join("", Arrays.copyOfRange(fields, start + 3, fields.length));
            if (fields[type].equalsIgnoreCase("DNSKEY")) {
                if (protocolOrAlgorithm != 3 || java.util.Base64.getDecoder().decode(data).length == 0) {
                    throw new IllegalArgumentException("DNSKEY protocol or key encoding");
                }
            } else {
                if (!data.matches("(?:[0-9A-Fa-f]{2})+")) throw new IllegalArgumentException("DS digest encoding");
            }
        } catch (IllegalArgumentException | IndexOutOfBoundsException e) {
            throw new IOException("Malformed DS/DNSKEY anchor record", e);
        }
    }

    private record Anchors(List<String> records, boolean root) { }

    /** JNI owns a private context per call; cancellation is polled without interrupting servlet threads. */
    private static final class Client implements CAADNSClient {
        private final InetSocketAddress server;
        private final Anchors anchors;
        private final ValidationMode mode;
        private final AtomicBoolean closed = new AtomicBoolean();

        Client(InetSocketAddress server, Anchors anchors, ValidationMode mode) {
            this.server = server; this.anchors = anchors; this.mode = mode;
        }
        @Override public ValidationMode validationMode() { return mode; }

        @Override public LookupResult resolveCaa(DNSDomainName candidate, LookupBudget budget) throws DNSLookupException {
            checkOpen();
            budget.reserveQuery();
            Duration remaining = budget.remaining();
            Duration cap = budget.queryTimeout();
            Duration timeout = remaining.compareTo(cap) < 0 ? remaining : cap;
            long millis = Math.min(60000, timeout.toMillis());
            if (millis < 1) throw failure(DNSLookupException.Reason.TIMEOUT, "CAA deadline exceeded", null);
            try {
                NativeResult result = queryNative(server.getAddress().getAddress(), server.getPort(),
                        candidate.asciiAbsoluteName(), 257, (int)millis, anchors.records().toArray(String[]::new), anchors.root(), closed);
                checkOpen();
                if (budget.remaining().isZero()) throw failure(DNSLookupException.Reason.TIMEOUT, "CAA deadline exceeded", null);
                if (result.bogus() || (mode == ValidationMode.LOCAL_ENFORCING && !anchors.root() && !result.secure())) {
                    throw failure(DNSLookupException.Reason.VALIDATION_FAILURE, "DNSSEC validation failed or lacks trust coverage", null);
                }
                if (result.rcode() != 0 && result.rcode() != 3) {
                    throw failure(DNSLookupException.Reason.RCODE_FAILURE, "Native resolver returned an error", null);
                }
                return UnboundCAAResponse.decode(candidate, result, server.toString(), mode, budget, Instant.now());
            } catch (NativeValidationException e) {
                throw failure(DNSLookupException.Reason.VALIDATION_FAILURE, "Cannot establish DNSSEC root trust", e);
            } catch (SocketTimeoutException e) {
                throw failure(DNSLookupException.Reason.TIMEOUT, "Native DNS query timed out", e);
            } catch (IOException | IllegalArgumentException e) {
                DNSLookupException.Reason reason = closed.get() || Thread.currentThread().isInterrupted()
                        ? DNSLookupException.Reason.CANCELLED : DNSLookupException.Reason.MALFORMED_RESPONSE;
                throw failure(reason, "Native DNS query could not establish complete CAA data", e);
            }
        }
        private void checkOpen() throws DNSLookupException {
            if (closed.get()) throw failure(DNSLookupException.Reason.CANCELLED, "Native DNS client closed", null);
        }
        @Override public void close() { closed.set(true); }
    }

    /** Detached, bounded copy of ub_result. Never exposes native pointers to Java. */
    record NativeResult(String canonicalName, int rcode, byte[][] data, int ttl,
            boolean secure, boolean bogus, String bogusReason, boolean haveData, boolean nameError, byte[] packet) {
        NativeResult {
            data = Arrays.stream(data).map(byte[]::clone).toArray(byte[][]::new);
            packet = packet.clone();
        }
        @Override public byte[][] data() { return Arrays.stream(data).map(byte[]::clone).toArray(byte[][]::new); }
        @Override public byte[] packet() { return packet.clone(); }
    }

    /** Typed native failure; never infer DNSSEC state by parsing exception text. */
    private static final class NativeValidationException extends IOException {
        private static final long serialVersionUID = 1L;
        private NativeValidationException(String message) { super(message); }
    }

    private static native NativeResult queryNative(byte[] address, int port, String name, int type,
            int timeout, String[] anchors, boolean validateRoot, AtomicBoolean cancelled) throws IOException;
    private static native void checkAnchorsNative(String[] anchors);

    static DNSLookupException failure(DNSLookupException.Reason reason, String message, Throwable cause) {
        var error = new DNSLookupException(new DNSLookupException.Failure(reason, message, List.of()));
        if (cause != null) error.initCause(cause);
        return error;
    }
}
