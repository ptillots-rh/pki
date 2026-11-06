// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later
package org.dogtagpki.acme.caa.libunbound;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;

import org.dogtagpki.acme.caa.CAADNSClient;
import org.dogtagpki.acme.caa.CAAPolicy;
import org.dogtagpki.acme.caa.DNSDomainName;
import org.dogtagpki.acme.caa.TestCAALookupBudget;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

/** Binary evidence checks use detached results and never load JNI or perform DNS I/O. */
class UnboundCAAResponseTest {
    private static final DNSDomainName NAME = new DNSDomainName("www.example.com.");
    private static final Name OWNER = Name.fromConstantString(NAME.asciiAbsoluteName());

    @Test void duplicateDataCannotHideAnOmittedRestrictiveRecord() throws Exception {
        var allow = caa("ca.example"); var deny = caa(";");
        var mixed = response(allow, deny);
        assertThrows(IOException.class, () -> decode(result(mixed,
                new byte[][] {allow.rdataToWireCanonical(), allow.rdataToWireCanonical()}, null, 60)));
        var duplicates = response(allow, allow);
        assertThrows(IOException.class, () -> decode(result(duplicates,
                new byte[][] {allow.rdataToWireCanonical(), deny.rdataToWireCanonical()}, null, 60)));
    }

    @Test void canonicalNameMustMatchTheConnectedAnswer() throws Exception {
        var record = caa("ca.example");
        assertThrows(IOException.class, () -> decode(result(response(record),
                new byte[][] {record.rdataToWireCanonical()}, "other.example.com.", 60)));
    }

    @Test void unrelatedSoaCannotEstablishCaaAbsence() throws Exception {
        var response = response();
        response.addRecord(soa("other.net."), Section.AUTHORITY);
        assertThrows(IOException.class, () -> decode(result(response, new byte[0][], null, 60)));
    }

    @Test void anUnresolvedReferralIsNotACompletedNegativeAnswer() throws Exception {
        var response = response();
        response.addRecord(new NSRecord(Name.fromConstantString("example.com."), 1, 60,
                Name.fromConstantString("ns.example.com.")), Section.AUTHORITY);
        assertThrows(IOException.class, () -> decode(result(response, new byte[0][], null, 60)));
    }

    @Test void loopingCompressionAndOversizedCountsAreRejectedBeforeRecordParsing() throws Exception {
        var packet = response().toWire();
        byte[] loop = packet.clone(); loop[12] = (byte) 0xc0; loop[13] = 12;
        assertThrows(IOException.class, () -> decode(raw(loop)));
        byte[] count = packet.clone(); count[6] = 4; count[7] = 1;
        assertThrows(IOException.class, () -> decode(raw(count)));
    }

    @Test void trailingBytesCannotBeIgnoredAsAnUnrelatedPacket() throws Exception {
        byte[] packet = response().toWire();
        assertThrows(IOException.class, () -> decode(raw(Arrays.copyOf(packet, packet.length + 1))));
    }

    @Test void aDnameAndItsSynthesizedCnameMustAgree() throws Exception {
        var response = response(new DNAMERecord(Name.fromConstantString("example.com."), 1, 60,
                Name.fromConstantString("target.net.")),
                new CNAMERecord(OWNER, 1, 60, Name.fromConstantString("wrong.target.net.")));
        assertThrows(IOException.class, () -> decode(result(response, new byte[0][], "wrong.target.net.", 60)));
    }

    @Test void nativeLifetimeCapsRecordLifetimeWithoutChangingItsPolicy() throws Exception {
        var record = caa("ca.example");
        var decoded = decode(result(response(record), new byte[][] {record.rdataToWireCanonical()}, null, 7));
        assertEquals(7, decoded.records().get(0).ttlSeconds());
        assertArrayEquals(record.getValueAsByteArray(), decoded.records().get(0).value());
    }

    @Test void detachedNativeBuffersCannotBeMutatedByEitherCaller() {
        byte[][] values = {{1, 2}};
        byte[] packet = response().toWire(); byte[] original = packet.clone();
        var result = new LibUnboundCAAProvider.NativeResult(null, 0, values, 60, false, false, null, true, false, packet);
        values[0][0] = 9; packet[0] = 9;
        result.data()[0][1] = 9; result.packet()[1] = 9;
        assertArrayEquals(new byte[] {1, 2}, result.data()[0]);
        assertArrayEquals(original, result.packet());
    }

    private static CAADNSClient.LookupResult decode(LibUnboundCAAProvider.NativeResult result) throws Exception {
        return UnboundCAAResponse.decode(NAME, result, "fixture", CAADNSClient.ValidationMode.UNCHECKED,
                new TestCAALookupBudget(new CAAPolicy(Set.of("ca.example")).limits()), Instant.now());
    }

    private static LibUnboundCAAProvider.NativeResult raw(byte[] packet) {
        return new LibUnboundCAAProvider.NativeResult(null, 0, new byte[0][], 60, false, false, null, false, false, packet);
    }

    private static LibUnboundCAAProvider.NativeResult result(Message response, byte[][] data, String canonical, int ttl) {
        return new LibUnboundCAAProvider.NativeResult(canonical, response.getRcode(), data, ttl,
                false, false, null, data.length != 0, response.getRcode() == Rcode.NXDOMAIN, response.toWire());
    }

    private static CAARecord caa(String value) { return new CAARecord(OWNER, 1, 60, 0, "issue", value); }
    private static SOARecord soa(String name) {
        return new SOARecord(Name.fromConstantString(name), 1, 60, Name.fromConstantString("ns.example.com."),
                Name.fromConstantString("hostmaster.example.com."), 1, 60, 60, 60, 60);
    }
    private static Message response(Record... records) {
        var response = Message.newQuery(Record.newRecord(OWNER, Type.CAA, DClass.IN));
        response.getHeader().setFlag(Flags.QR); response.getHeader().setFlag(Flags.RA);
        for (var record : records) response.addRecord(record, Section.ANSWER);
        return response;
    }
}
