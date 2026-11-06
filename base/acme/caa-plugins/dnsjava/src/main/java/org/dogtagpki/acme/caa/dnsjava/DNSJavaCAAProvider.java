// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa.dnsjava;

import java.io.ByteArrayInputStream;
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
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.dogtagpki.acme.caa.CAADNSClient;
import org.dogtagpki.acme.caa.CAADNSClientProvider;
import org.dogtagpki.acme.caa.DNSDomainName;
import org.dogtagpki.acme.caa.DNSLookupException;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNAMERecord;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.ExtendedFlags;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Master;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Opcode;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;
import org.xbill.DNS.WireParseException;
import org.xbill.DNS.dnssec.ValidatingResolver;

/** TCP DNS adapter; all dnsjava types stay behind the shared CAA interface. */
public class DNSJavaCAAProvider implements CAADNSClientProvider {
    private static final Set<String> CONFIGURATION_KEYS = Set.of("server", "port", "trustAnchors");
    private static final int MAX_RESPONSE_RECORDS = 1024;
    private static final int MAX_DIAGNOSTIC_LENGTH = 1024;

    @Override
    public CAADNSClient.ValidationMode validationMode() {
        return CAADNSClient.ValidationMode.UNCHECKED;
    }

    /** Separate fixed-behavior provider for an operator-managed local validating resolver. */
    public static final class LocalValidatingResolver extends DNSJavaCAAProvider {
        @Override
        public CAADNSClient.ValidationMode validationMode() {
            return CAADNSClient.ValidationMode.DELEGATED_ENFORCING;
        }
    }

    /** In-process dnsjava validation, with explicitly configured static trust anchors. */
    public static final class Validating extends DNSJavaCAAProvider {
        @Override
        public CAADNSClient.ValidationMode validationMode() {
            return CAADNSClient.ValidationMode.LOCAL_ENFORCING;
        }
    }

    /** Uses explicit numeric endpoints; provider selection fixes validation behavior. */
    @Override
    public CAADNSClient open(Config config) throws DNSLookupException {
        if (!CONFIGURATION_KEYS.containsAll(config.settings().keySet()) || config.settings().get("server") == null) {
            throw failure(DNSLookupException.Reason.CONFIGURATION, "Unknown or missing DNS setting", List.of());
        }
        try {
            String server = config.settings().get("server");
            // Reject hostnames before getByName(), which can otherwise perform
            // a bootstrap lookup through the machine's system DNS configuration.
            if (!server.matches("[0-9.]+") && !(server.contains(":") && server.matches("[0-9A-Fa-f:.]+"))) {
                throw new IllegalArgumentException("Numeric resolver address required");
            }
            InetAddress address = InetAddress.getByName(server);
            int port = Integer.parseInt(config.settings().getOrDefault("port", "53"));
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Invalid port");
            }
            CAADNSClient.ValidationMode mode = validationMode();
            if (mode == CAADNSClient.ValidationMode.DELEGATED_ENFORCING && !address.isLoopbackAddress()) {
                throw new IllegalArgumentException("Unsupported validation deployment");
            }
            String anchorFile = config.settings().get("trustAnchors");
            if ((mode == CAADNSClient.ValidationMode.LOCAL_ENFORCING) != (anchorFile != null)) {
                throw new IllegalArgumentException("Trust anchors must match the selected provider");
            }
            TrustAnchors anchors = anchorFile == null ? null : readTrustAnchors(Path.of(anchorFile));
            return new Client(mode, new InetSocketAddress(address, port), anchors);
        } catch (IOException | IllegalArgumentException e) {
            throw failure(DNSLookupException.Reason.CONFIGURATION, "Invalid DNS adapter configuration", List.of(), e);
        }
    }

    /** Snapshot explicit records, never interpreting RFC 5011 state as a list of trusted keys. */
    private static TrustAnchors readTrustAnchors(Path path) throws IOException {
        byte[] bytes;
        try (var input = Files.newInputStream(path)) {
            bytes = input.readNBytes(1024 * 1024 + 1);
        }
        if (bytes.length > 1024 * 1024) throw new IOException("Anchor file exceeds limit");
        for (byte value : bytes) {
            if (value < 0 || (value < 32 && value != '\n' && value != '\r' && value != '\t')) {
                throw new IOException("Non-ASCII anchor file");
            }
        }
        List<String> records = new ArrayList<>();
        boolean root = false;
        for (String line : new String(bytes, StandardCharsets.US_ASCII).split("\\R")) {
            if (line.matches("(?i).*\\bstate\\s*=.*")
                    || line.toLowerCase(java.util.Locale.ROOT).contains("autotrust trust anchor")) {
                throw new IOException("Managed anchors require an explicit static trusted-key export");
            }
            String text = line.split(";", 2)[0].strip();
            if (text.isEmpty()) continue;
            if (records.size() == 128 || text.length() > 8192
                    || !text.matches("(?i)\\S+\\s+(?:[0-9]+\\s+)?IN\\s+(?:DS|DNSKEY)\\s+[^()]+")) {
                throw new IOException("Expected a single-line DS or DNSKEY anchor");
            }
            try (var master = new Master(new ByteArrayInputStream(text.getBytes(StandardCharsets.US_ASCII)),
                    Name.root, 0)) {
                Record record = master.nextRecord();
                if (!(record instanceof DSRecord) && !(record instanceof DNSKEYRecord)) {
                    throw new IOException("Expected DS or DNSKEY anchor");
                }
                if (record instanceof DNSKEYRecord key && (key.getProtocol() != 3
                        || (key.getFlags() & 256) == 0 || (key.getFlags() & 128) != 0)) {
                    throw new IOException("Expected a nonrevoked DNSSEC zone key");
                }
                root |= record.getName().equals(Name.root);
                records.add(record.toString());
            }
        }
        if (records.isEmpty()) throw new IOException("Empty trust-anchor file");
        return new TrustAnchors(String.join("\n", records) + "\n", root);
    }

    private record TrustAnchors(String records, boolean root) { }

    /** One immutable client configuration, with per-call resolver/deadline state. */
    private static final class Client implements CAADNSClient {
        private final ValidationMode mode;
        private final InetSocketAddress server;
        private final TrustAnchors anchors;
        private final AtomicBoolean closed = new AtomicBoolean();
        private final Set<CompletableFuture<Message>> pending = ConcurrentHashMap.newKeySet();
        private final Set<ValidationTransport> validations = ConcurrentHashMap.newKeySet();

        private Client(ValidationMode mode, InetSocketAddress server, TrustAnchors anchors) {
            this.mode = mode;
            this.server = server;
            this.anchors = anchors;
        }

        @Override
        public ValidationMode validationMode() {
            return mode;
        }

        /** Resolves one candidate through aliases; parent search stays in the engine. */
        @Override
        public LookupResult resolveCaa(DNSDomainName candidate, LookupBudget budget) throws DNSLookupException {
            List<ResponseEvidence> evidence = new ArrayList<>();
            List<AliasStep> aliases = new ArrayList<>();
            Set<Name> visited = new HashSet<>();
            ValidationTransport transport = null;
            try {
                Name current = Name.fromString(candidate.asciiAbsoluteName());
                if (current.equals(Name.root)) {
                    throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE, "Root CAA lookup is not supported", evidence);
                }
                Resolver validator = null;
                if (anchors != null) {
                    transport = new ValidationTransport(budget);
                    validations.add(transport);
                    var local = new ValidatingResolver(transport);
                    // Constructor initialization reads JVM properties. Replace
                    // its settings/anchors with this client's explicit policy.
                    local.init(new Properties());
                    local.getTrustAnchors().clear();
                    local.setAddReasonToAdditional(false);
                    local.loadTrustAnchors(new ByteArrayInputStream(
                            anchors.records().getBytes(StandardCharsets.US_ASCII)));
                    validator = local;
                    if (anchors.root()) {
                        Message root = exchange(Name.root, Type.DNSKEY, budget, evidence, validator);
                        if (!root.getHeader().getFlag(Flags.AD)) {
                            throw failure(DNSLookupException.Reason.VALIDATION_FAILURE,
                                    "Cannot establish DNSSEC root trust", evidence);
                        }
                    }
                }
                visited.add(current);
                while (true) {
                    checkOpen(evidence);
                    Message response = exchange(current, Type.CAA, budget, evidence, validator);
                    List<Record> answers = response.getSection(Section.ANSWER);
                    boolean followed = false;
                    while (true) {
                        Name owner = current;
                        List<Record> owned = answers.stream().filter(r -> r.getName().equals(owner)).toList();
                        if (owned.stream().anyMatch(r -> r.getDClass() != DClass.IN)) {
                            throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE, "Unexpected answer class", evidence);
                        }
                        List<org.xbill.DNS.CAARecord> caa = owned.stream()
                                .filter(r -> r instanceof org.xbill.DNS.CAARecord)
                                .map(r -> (org.xbill.DNS.CAARecord) r).toList();
                        List<CNAMERecord> cnames = owned.stream().filter(r -> r instanceof CNAMERecord)
                                .map(r -> (CNAMERecord) r).toList();
                        DNAMERecord dname = closestDname(answers, current, evidence);
                        if (!caa.isEmpty()) {
                            if (!cnames.isEmpty() || dname != null || response.getRcode() != Rcode.NOERROR) {
                                throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE, "Conflicting terminal CAA data", evidence);
                            }
                            DNSDomainName terminal = domain(current);
                            List<CAADNSClient.CAARecord> records = caa.stream().map(r -> new CAADNSClient.CAARecord(
                                    terminal, r.getTTL(), r.getFlags(), r.getTag(), r.getValueAsByteArray())).toList();
                            return new LookupResult(candidate, terminal, LookupKind.RRSET, records,
                                    aliases, evidence, Optional.empty());
                        }
                        Set<Name> targets = new HashSet<>();
                        cnames.forEach(r -> targets.add(r.getTarget()));
                        if (targets.size() > 1) {
                            throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE, "Conflicting CNAME targets", evidence);
                        }
                        Name target = cnames.isEmpty() ? null : cnames.get(0).getTarget();
                        if (dname != null) {
                            Name synthesized = current.fromDNAME(dname);
                            if (target != null && !target.equals(synthesized)) {
                                throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE, "Invalid DNAME synthesis", evidence);
                            }
                            target = synthesized;
                        }
                        if (target == null) {
                            break;
                        }
                        budget.reserveAlias();
                        if (!visited.add(target)) {
                            throw failure(DNSLookupException.Reason.ALIAS_LOOP, "DNS alias loop", evidence);
                        }
                        long ttl = cnames.isEmpty() ? dname.getTTL() : cnames.get(0).getTTL();
                        if (dname != null) ttl = Math.min(ttl, dname.getTTL());
                        aliases.add(new AliasStep(domain(current), domain(target),
                                dname == null ? AliasKind.CNAME : AliasKind.DNAME_SYNTHESIS, ttl));
                        current = target;
                        followed = true;
                    }
                    DNSDomainName terminal = domain(current);
                    List<Record> authority = response.getSection(Section.AUTHORITY);
                    SOARecord soa = closestNegativeSoa(authority, current, evidence);
                    LookupKind kind;
                    if (response.getRcode() == Rcode.NXDOMAIN) {
                        kind = LookupKind.NXDOMAIN;
                    } else if (soa != null) {
                        kind = LookupKind.NODATA;
                    } else if (authority.stream().anyMatch(r -> r.getType() == Type.NS)) {
                        throw failure(DNSLookupException.Reason.INCOMPLETE_ANSWER, "Unresolved DNS referral", evidence);
                    } else if (followed) {
                        // An alias-only reply is not terminal absence. Query its target.
                        continue;
                    } else if (answers.stream().anyMatch(r -> r.getType() != Type.RRSIG)) {
                        throw failure(DNSLookupException.Reason.INCOMPLETE_ANSWER, "Unrelated answer is not CAA absence", evidence);
                    } else {
                        // A successful empty recursive answer can establish
                        // absence without supplying SOA negative-cache metadata.
                        kind = LookupKind.NODATA;
                    }
                    Optional<SOAEvidence> soaEvidence = soa == null ? Optional.empty()
                            : Optional.of(new SOAEvidence(domain(soa.getName()), soa.getTTL(), soa.getMinimum()));
                    return new LookupResult(candidate, terminal, kind, List.of(), aliases, evidence,
                            Optional.of(new NegativeEvidence(terminal, kind, soaEvidence)));
                }
            } catch (DNSLookupException e) {
                // Preserve already consumed alias responses on a failed follow-up.
                if (e.failure().partialResponses().isEmpty() && !evidence.isEmpty()) {
                    throw failure(e.failure().reason(), e.failure().message(), evidence, e);
                }
                throw e;
            } catch (IOException | IllegalArgumentException e) {
                throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE, "Unsupported or malformed DNS data", evidence, e);
            } catch (RuntimeException e) {
                throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE, "Unable to interpret DNS response", evidence, e);
            } finally {
                if (transport != null) {
                    transport.cancel();
                    validations.remove(transport);
                }
            }
        }

        private Message exchange(Name current, int type, LookupBudget budget,
                List<ResponseEvidence> evidence, Resolver validator)
                throws DNSLookupException, IOException {
            if (validator == null) budget.reserveQuery();
            // Read the moving deadline once, then cap this exchange by the
            // per-query allowance. Re-reading could produce a different timeout.
            Duration remaining = budget.remaining();
            Duration queryTimeout = budget.queryTimeout();
            Duration timeout = remaining.compareTo(queryTimeout) < 0 ? remaining : queryTimeout;
            if (timeout.isZero() || timeout.isNegative()) {
                throw failure(DNSLookupException.Reason.TIMEOUT, "CAA lookup deadline exceeded", evidence);
            }
            Message query = Message.newQuery(Record.newRecord(current, type, DClass.IN));
            query.getHeader().setFlag(Flags.RD);
            query.getHeader().unsetFlag(Flags.CD);
            SimpleResolver resolver = new SimpleResolver(server);
            resolver.setTCP(true);
            resolver.setTimeout(timeout);
            if (validationMode() == ValidationMode.DELEGATED_ENFORCING) {
                query.getHeader().setFlag(Flags.AD);
                resolver.setEDNS(0, 0, ExtendedFlags.DO);
            }
            CompletableFuture<Message> future = (validator == null ? resolver : validator)
                    .sendAsync(query).toCompletableFuture();
            pending.add(future);
            try {
                if (closed.get()) {
                    future.cancel(true);
                }
                Message response = future.get(timeout.toNanos(), TimeUnit.NANOSECONDS);
                checkOpen(evidence);
                if (budget.remaining().isZero()) {
                    throw failure(DNSLookupException.Reason.TIMEOUT, "CAA lookup deadline exceeded", evidence);
                }
                if (!response.getHeader().getFlag(Flags.QR) || response.getHeader().getID() != query.getHeader().getID()
                        || response.getHeader().getOpcode() != Opcode.QUERY
                        || response.getHeader().getCount(Section.QUESTION) != 1
                        || !query.getQuestion().equals(response.getQuestion())) {
                    throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE, "Mismatched DNS response", evidence);
                }
                evidence.add(observe(current, response));
                if (response.getHeader().getFlag(Flags.TC) || (mode != ValidationMode.LOCAL_ENFORCING
                        && (!response.getHeader().getFlag(Flags.RA) || response.getHeader().getFlag(Flags.CD)))) {
                    throw failure(DNSLookupException.Reason.INCOMPLETE_ANSWER, "Incomplete or nonrecursive DNS response", evidence);
                }
                int count = response.getSection(Section.ANSWER).size() + response.getSection(Section.AUTHORITY).size()
                        + response.getSection(Section.ADDITIONAL).size();
                if (count > MAX_RESPONSE_RECORDS) {
                    throw failure(DNSLookupException.Reason.LIMIT_EXCEEDED, "DNS response record limit exceeded", evidence);
                }
                if (response.getRcode() != Rcode.NOERROR && response.getRcode() != Rcode.NXDOMAIN) {
                    // RFC 8914 codes 5-12 describe DNSSEC validation failures.
                    // EDE refines an already failing response; it never promotes
                    // AD-clear data to validated data or changes RCODE handling.
                    boolean validationFailure = (mode == ValidationMode.LOCAL_ENFORCING
                            && response.getRcode() == Rcode.SERVFAIL)
                            || mode == ValidationMode.DELEGATED_ENFORCING
                            && response.getRcode() == Rcode.SERVFAIL && response.getOPT() != null
                            && response.getOPT().getOptions().stream()
                                    .filter(ExtendedErrorCodeOption.class::isInstance)
                                    .map(ExtendedErrorCodeOption.class::cast)
                                    .anyMatch(error -> error.getErrorCode() >= 5 && error.getErrorCode() <= 12);
                    throw failure(validationFailure ? DNSLookupException.Reason.VALIDATION_FAILURE
                            : DNSLookupException.Reason.RCODE_FAILURE, "DNS resolver returned an error", evidence);
                }
                if (mode == ValidationMode.LOCAL_ENFORCING && !anchors.root()
                        && !response.getHeader().getFlag(Flags.AD)) {
                    throw failure(DNSLookupException.Reason.VALIDATION_FAILURE,
                            "DNSSEC result lacks trust-anchor coverage", evidence);
                }
                return response;
            } catch (TimeoutException e) {
                throw failure(DNSLookupException.Reason.TIMEOUT, "DNS query timed out", evidence, e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw failure(DNSLookupException.Reason.CANCELLED, "DNS query interrupted", evidence, e);
            } catch (CancellationException e) {
                throw failure(DNSLookupException.Reason.CANCELLED, "DNS query cancelled", evidence, e);
            } catch (ExecutionException e) {
                throw failure(exchangeFailureReason(e.getCause()), "DNS exchange failed", evidence, e);
            } finally {
                pending.remove(future);
                if (!future.isDone()) {
                    future.cancel(true);
                }
            }
        }

        private DNSLookupException.Reason exchangeFailureReason(Throwable cause) {
            while (cause instanceof CompletionException && cause.getCause() != null) cause = cause.getCause();
            if (cause instanceof DNSLookupException lookup) return lookup.failure().reason();
            if (cause instanceof CancellationException) return DNSLookupException.Reason.CANCELLED;
            if (cause instanceof WireParseException) {
                return DNSLookupException.Reason.MALFORMED_RESPONSE;
            }
            if (cause instanceof TimeoutException || cause instanceof SocketTimeoutException) {
                return DNSLookupException.Reason.TIMEOUT;
            }
            return mode == ValidationMode.LOCAL_ENFORCING && !(cause instanceof IOException)
                    ? DNSLookupException.Reason.VALIDATION_FAILURE : DNSLookupException.Reason.UNREACHABLE;
        }

        private ResponseEvidence observe(Name question, Message response) {
            boolean delegated = validationMode() == ValidationMode.DELEGATED_ENFORCING;
            boolean authenticatedData = response.getHeader().getFlag(Flags.AD);
            DNSSECStatus status = DNSSECStatus.UNCHECKED;
            ValidationAssurance assurance = ValidationAssurance.NONE;
            if (delegated) {
                // AD only conveys assurance under the trusted enforcing-resolver
                // contract. AD clear does not prove that the zone is unsigned.
                status = authenticatedData ? DNSSECStatus.SECURE : DNSSECStatus.UNCLASSIFIED;
                assurance = ValidationAssurance.TRUSTED_RESOLVER;
            } else if (mode == ValidationMode.LOCAL_ENFORCING
                    && (response.getRcode() == Rcode.NOERROR || response.getRcode() == Rcode.NXDOMAIN)
                    && (authenticatedData || (anchors.root() && !question.equals(Name.root)))) {
                // This AD flag is set by our validator, not trusted from the wire.
                // Insecurity is accepted only with established root coverage.
                status = authenticatedData ? DNSSECStatus.SECURE : DNSSECStatus.PROVEN_INSECURE;
                assurance = ValidationAssurance.LOCAL_VALIDATOR;
            }
            Optional<ExtendedError> diagnostic = Optional.empty();
            if (response.getOPT() != null) {
                diagnostic = response.getOPT().getOptions().stream()
                        .filter(ExtendedErrorCodeOption.class::isInstance)
                        .map(ExtendedErrorCodeOption.class::cast)
                        .findFirst().map(Client::extendedError);
            }
            return new ResponseEvidence(server.toString(), domain(question), response.getRcode(), authenticatedData,
                    status, assurance, Instant.now(), "TCP", diagnostic);
        }

        /** Resolver-supplied text is diagnostic only; bound and flatten it before retaining it. */
        private static ExtendedError extendedError(ExtendedErrorCodeOption option) {
            Optional<String> text = Optional.ofNullable(option.getText())
                    .map(value -> value.replaceAll("[\\p{Cntrl}]", " "))
                    .map(value -> value.substring(0, Math.min(MAX_DIAGNOSTIC_LENGTH, value.length())));
            return new ExtendedError(option.getErrorCode(), text);
        }

        private void checkOpen(List<ResponseEvidence> evidence) throws DNSLookupException {
            if (closed.get()) {
                throw failure(DNSLookupException.Reason.CANCELLED, "DNS client is closed", evidence);
            }
        }

        @Override
        public void close() {
            closed.set(true);
            pending.forEach(future -> future.cancel(true));
            validations.forEach(ValidationTransport::cancel);
        }

        /** Bound every supporting DNSKEY/DS query and stop follow-on work after cancellation. */
        private final class ValidationTransport extends SimpleResolver {
            private final LookupBudget budget;
            private final AtomicBoolean stopped = new AtomicBoolean();
            private final Set<CompletableFuture<Message>> requests = ConcurrentHashMap.newKeySet();

            ValidationTransport(LookupBudget budget) {
                super(server);
                this.budget = budget;
                setTCP(true);
            }

            @Override
            public CompletionStage<Message> sendAsync(Message query, Executor executor) {
                try {
                    checkOpen(List.of());
                    if (stopped.get()) throw failure(DNSLookupException.Reason.CANCELLED,
                            "DNSSEC validation stopped", List.of());
                    budget.reserveQuery();
                    Duration left = budget.remaining();
                    if (left.isZero() || left.isNegative()) {
                        throw failure(DNSLookupException.Reason.TIMEOUT, "DNSSEC deadline exceeded", List.of());
                    }
                    setTimeout(left.compareTo(budget.queryTimeout()) < 0 ? left : budget.queryTimeout());
                    CompletableFuture<Message> request = super.sendAsync(query, executor).toCompletableFuture();
                    requests.add(request);
                    if (closed.get() || stopped.get()) request.cancel(true);
                    return request.whenComplete((value, error) -> requests.remove(request)).thenApply(response -> {
                        if (!response.getHeader().getFlag(Flags.QR)
                                || response.getHeader().getID() != query.getHeader().getID()
                                || response.getHeader().getOpcode() != Opcode.QUERY
                                || response.getHeader().getCount(Section.QUESTION) != 1
                                || !query.getQuestion().equals(response.getQuestion())
                                || response.getHeader().getFlag(Flags.TC)
                                || response.getSection(Section.ANSWER).size()
                                        + response.getSection(Section.AUTHORITY).size()
                                        + response.getSection(Section.ADDITIONAL).size() > MAX_RESPONSE_RECORDS) {
                            throw new CompletionException(failure(DNSLookupException.Reason.MALFORMED_RESPONSE,
                                    "Invalid DNSSEC supporting response", List.of()));
                        }
                        // The library must never accept upstream AD as local validation.
                        response.getHeader().unsetFlag(Flags.AD);
                        return response;
                    });
                } catch (DNSLookupException | RuntimeException e) {
                    return CompletableFuture.failedFuture(e);
                }
            }

            void cancel() {
                stopped.set(true);
                requests.forEach(request -> request.cancel(true));
            }
        }
    }

    private static DNAMERecord closestDname(List<Record> records, Name name, List<CAADNSClient.ResponseEvidence> evidence)
            throws DNSLookupException {
        DNAMERecord result = null;
        for (Record record : records) {
            if (!(record instanceof DNAMERecord dname)) {
                continue;
            }
            // DNAME redirects descendants, not the name at the DNAME owner.
            if (!name.subdomain(dname.getName()) || name.equals(dname.getName())) {
                continue;
            }
            boolean conflictingTarget = result != null && result.getName().equals(dname.getName())
                    && !result.getTarget().equals(dname.getTarget());
            if (dname.getDClass() != DClass.IN || conflictingTarget) {
                throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE, "Invalid or conflicting DNAME", evidence);
            }
            if (result == null || dname.getName().labels() > result.getName().labels()) {
                result = dname;
            }
        }
        return result;
    }

    /** Selects the most specific enclosing SOA for the terminal negative answer. */
    private static SOARecord closestNegativeSoa(List<Record> authority, Name terminal,
            List<CAADNSClient.ResponseEvidence> evidence) throws DNSLookupException {
        SOARecord closest = null;
        for (Record record : authority) {
            if (!(record instanceof SOARecord soa)) {
                continue;
            }
            if (soa.getDClass() != DClass.IN || !terminal.subdomain(soa.getName())) {
                throw failure(DNSLookupException.Reason.INCOMPLETE_ANSWER, "Unrelated negative SOA", evidence);
            }
            if (closest == null || soa.getName().labels() > closest.getName().labels()) {
                closest = soa;
            }
        }
        return closest;
    }

    private static DNSDomainName domain(Name name) {
        return new DNSDomainName(name.toString());
    }

    private static DNSLookupException failure(DNSLookupException.Reason reason, String message,
            List<CAADNSClient.ResponseEvidence> evidence) {
        return new DNSLookupException(new DNSLookupException.Failure(reason, message, evidence));
    }
    /** Preserve the underlying cause without copying it into the public failure message. */
    private static DNSLookupException failure(DNSLookupException.Reason reason, String message,
            List<CAADNSClient.ResponseEvidence> evidence, Throwable cause) {
        DNSLookupException exception = failure(reason, message, evidence);
        exception.initCause(cause);
        return exception;
    }

}
