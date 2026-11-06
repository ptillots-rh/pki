// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa.libunbound;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import org.dogtagpki.acme.caa.CAADNSClient;
import org.dogtagpki.acme.caa.DNSDomainName;
import org.dogtagpki.acme.caa.DNSLookupException;

/**
 * Reads evidence from libunbound's completed answer packet, not from a socket.
 * libunbound handles transport, recursion and validation. This bounded reader
 * retains CAA, aliases and negative SOA metadata and cross-checks ub_result.
 */
final class UnboundCAAResponse {
    private final byte[] bytes;
    private int pos;

    private UnboundCAAResponse(byte[] bytes) throws IOException {
        if (bytes.length < 12 || bytes.length > 65535) throw new IOException("Invalid native DNS packet size");
        this.bytes = bytes;
    }

    static CAADNSClient.LookupResult decode(DNSDomainName candidate, LibUnboundCAAProvider.NativeResult nativeResult,
            String resolver, CAADNSClient.ValidationMode mode, CAADNSClient.LookupBudget budget, Instant received)
            throws IOException, DNSLookupException {
        var packet = new UnboundCAAResponse(nativeResult.packet());
        packet.u16(); // library-generated ID has no application query to correlate
        int flags = packet.u16();
        int questions = packet.u16(), answers = packet.u16(), authority = packet.u16(), additional = packet.u16();
        if ((flags & 0x8000) == 0 || (flags & 0x7a00) != 0 || questions != 1
                || answers + authority + additional > 1024 || (flags & 15) != nativeResult.rcode()) {
            throw new IOException("Incomplete or inconsistent native DNS header");
        }
        if (!packet.name().equals(candidate) || packet.u16() != 257 || packet.u16() != 1) {
            throw new IOException("Native DNS question mismatch");
        }
        List<Resource> answer = packet.records(answers);
        List<Resource> authorities = packet.records(authority);
        packet.records(additional);
        if (packet.pos != packet.bytes.length || nativeResult.ttl() < 0
                || nativeResult.nameError() != (nativeResult.rcode() == 3)) {
            throw new IOException("Native DNS result metadata mismatch");
        }
        var current = candidate;
        List<CAADNSClient.AliasStep> aliases = new ArrayList<>();
        var visited = new HashSet<DNSDomainName>();
        visited.add(current);
        while (true) {
            Resource cname = null, dname = null;
            for (Resource record : answer) {
                if (record.type == 5 && record.owner.equals(current)) {
                    if (cname != null && !cname.target.equals(record.target)) throw new IOException("Conflicting CNAME");
                    cname = record;
                }
                if (record.type == 39 && descendant(current, record.owner) && !current.equals(record.owner)
                        && (dname == null || record.owner.asciiAbsoluteName().length() >= dname.owner.asciiAbsoluteName().length())) {
                    if (dname != null && dname.owner.equals(record.owner) && !dname.target.equals(record.target)) {
                        throw new IOException("Conflicting DNAME");
                    }
                    dname = record;
                }
            }
            if (cname == null && dname == null) break;
            if (answer.stream().anyMatch(r -> r.type == 257 && visited.contains(r.owner))) {
                throw new IOException("CAA conflicts with alias");
            }
            DNSDomainName target = cname == null ? null : cname.target;
            if (dname != null) {
                String prefix = dname.owner.asciiAbsoluteName().equals(".") ? current.asciiAbsoluteName()
                        : current.asciiAbsoluteName().substring(0,
                                current.asciiAbsoluteName().length() - dname.owner.asciiAbsoluteName().length());
                String suffix = dname.target.asciiAbsoluteName();
                var synthesized = new DNSDomainName(prefix + (suffix.equals(".") ? "" : suffix));
                if (target != null && !target.equals(synthesized)) throw new IOException("Invalid DNAME synthesis");
                target = synthesized;
            }
            budget.reserveAlias();
            if (!visited.add(target)) throw LibUnboundCAAProvider.failure(DNSLookupException.Reason.ALIAS_LOOP, "Native DNS alias loop", null);
            long ttl = cname == null ? dname.ttl : cname.ttl;
            if (dname != null) ttl = Math.min(ttl, dname.ttl);
            aliases.add(new CAADNSClient.AliasStep(current, target,
                    dname == null ? CAADNSClient.AliasKind.CNAME : CAADNSClient.AliasKind.DNAME_SYNTHESIS, ttl));
            current = target;
        }
        final DNSDomainName terminal = current;
        if (nativeResult.canonicalName() != null && !new DNSDomainName(nativeResult.canonicalName()).equals(terminal)) {
            throw new IOException("Native canonical name differs from answer aliases");
        }
        List<Resource> caa = answer.stream().filter(r -> r.type == 257 && r.owner.equals(terminal)).toList();
        // Accept terminal data only when packet relevance and RDATA agree
        // with libunbound's structured ub_result.
        byte[][] data = nativeResult.data();
        if (caa.size() != data.length || nativeResult.haveData() != !caa.isEmpty()
                || caa.stream().anyMatch(r -> Arrays.stream(data).noneMatch(v -> Arrays.equals(v, r.data)))
                || Arrays.stream(data).anyMatch(v -> caa.stream().noneMatch(r -> Arrays.equals(v, r.data)))) {
            throw new IOException("Native terminal RDATA mismatch");
        }
        boolean local = mode == CAADNSClient.ValidationMode.LOCAL_ENFORCING;
        var status = !local ? CAADNSClient.DNSSECStatus.UNCHECKED : nativeResult.secure()
                ? CAADNSClient.DNSSECStatus.SECURE : CAADNSClient.DNSSECStatus.PROVEN_INSECURE;
        var evidence = new CAADNSClient.ResponseEvidence(resolver, candidate, nativeResult.rcode(), (flags & 32) != 0,
                status, local ? CAADNSClient.ValidationAssurance.LOCAL_VALIDATOR : CAADNSClient.ValidationAssurance.NONE,
                received, "libunbound/TCP", Optional.empty());
        if (!caa.isEmpty()) {
            if (nativeResult.rcode() != 0) throw new IOException("CAA in negative native result");
            List<CAADNSClient.CAARecord> records = new ArrayList<>();
            for (Resource record : caa) {
                if (record.data.length < 3) throw new IOException("Short CAA RDATA");
                int tagLength = Byte.toUnsignedInt(record.data[1]);
                if (tagLength == 0 || tagLength > record.data.length - 2) throw new IOException("Invalid CAA tag length");
                String tag = new String(record.data, 2, tagLength, StandardCharsets.US_ASCII);
                records.add(new CAADNSClient.CAARecord(terminal, Math.min(record.ttl, nativeResult.ttl()),
                        Byte.toUnsignedInt(record.data[0]), tag, Arrays.copyOfRange(record.data, 2 + tagLength, record.data.length)));
            }
            return new CAADNSClient.LookupResult(candidate, terminal, CAADNSClient.LookupKind.RRSET,
                    records, aliases, List.of(evidence), Optional.empty());
        }
        Resource soa = null;
        for (Resource record : authorities) {
            if (record.type == 6) {
                if (!descendant(terminal, record.owner)) throw new IOException("Unrelated negative SOA");
                if (soa == null || record.owner.asciiAbsoluteName().length() > soa.owner.asciiAbsoluteName().length()) soa = record;
            }
        }
        if (soa == null && (authorities.stream().anyMatch(r -> r.type == 2)
                || answer.stream().anyMatch(r -> r.type != 46))) {
            throw new IOException("Native result does not establish terminal absence");
        }
        var kind = nativeResult.rcode() == 3 ? CAADNSClient.LookupKind.NXDOMAIN : CAADNSClient.LookupKind.NODATA;
        Optional<CAADNSClient.SOAEvidence> negativeSoa = soa == null ? Optional.empty()
                : Optional.of(new CAADNSClient.SOAEvidence(soa.owner, soa.ttl, soa.minimum));
        return new CAADNSClient.LookupResult(candidate, terminal, kind, List.of(), aliases, List.of(evidence),
                Optional.of(new CAADNSClient.NegativeEvidence(terminal, kind, negativeSoa)));
    }

    private static boolean descendant(DNSDomainName name, DNSDomainName parent) {
        return parent.asciiAbsoluteName().equals(".") || name.equals(parent)
                || name.asciiAbsoluteName().endsWith("." + parent.asciiAbsoluteName());
    }

    private record Resource(DNSDomainName owner, int type, long ttl, byte[] data, DNSDomainName target, long minimum) { }

    private List<Resource> records(int count) throws IOException {
        List<Resource> records = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            DNSDomainName owner = name();
            int type = u16(), dnsClass = u16();
            long rawTtl = u32(), ttl = rawTtl > 0x7fffffffL ? 0 : rawTtl;
            int length = u16(), start = pos, end = start + length;
            require(length);
            if (type == 41) {
                if ((rawTtl >>> 24) != 0) throw new IOException("Extended DNS error RCODE");
            } else if (dnsClass != 1) throw new IOException("Unexpected DNS class");
            DNSDomainName target = null;
            long minimum = 0;
            if (type == 5 || type == 39) target = name();
            else if (type == 6) { name(); name(); u32(); u32(); u32(); u32(); minimum = u32(); }
            if ((type == 5 || type == 39 || type == 6) && pos != end) throw new IOException("Invalid DNS RDATA length");
            byte[] data = Arrays.copyOfRange(bytes, start, end);
            pos = end;
            records.add(new Resource(owner, type, ttl, data, target, minimum));
        }
        return records;
    }

    /** Compression pointers must point backward; limits bound name expansion and work. */
    private DNSDomainName name() throws IOException {
        int cursor = pos, resume = -1, steps = 0;
        StringBuilder text = new StringBuilder();
        while (true) {
            if (cursor >= bytes.length || ++steps > 255) throw new IOException("Invalid compressed DNS name");
            int length = Byte.toUnsignedInt(bytes[cursor++]);
            if ((length & 192) == 192) {
                if (cursor >= bytes.length) throw new IOException("Short DNS compression pointer");
                int pointer = ((length & 63) << 8) | Byte.toUnsignedInt(bytes[cursor++]);
                if (pointer >= cursor - 2) throw new IOException("Forward or looping DNS compression pointer");
                if (resume < 0) resume = cursor;
                cursor = pointer;
            } else if (length == 0) {
                pos = resume < 0 ? cursor : resume;
                return new DNSDomainName(text.length() == 0 ? "." : text.toString());
            } else {
                if (length > 63 || cursor + length > bytes.length || text.length() + length + 1 > 254) {
                    throw new IOException("Oversized DNS name");
                }
                for (int i = 0; i < length; i++) {
                    int value = Byte.toUnsignedInt(bytes[cursor++]);
                    if (!((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
                            || (value >= '0' && value <= '9') || value == '-' || value == '_')) {
                        throw new IOException("Unsupported DNS label octet");
                    }
                    text.append((char)value);
                }
                text.append('.');
            }
        }
    }

    private void require(int length) throws IOException {
        if (length < 0 || pos > bytes.length - length) throw new IOException("Truncated DNS record");
    }
    private int u16() throws IOException {
        require(2);
        int value = Byte.toUnsignedInt(bytes[pos]) * 256 + Byte.toUnsignedInt(bytes[pos + 1]);
        pos += 2;
        return value;
    }
    private long u32() throws IOException { return ((long)u16() << 16) | u16(); }
}
