// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa.dnsjava;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;
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
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.ExtendedFlags;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Opcode;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;
import org.xbill.DNS.WireParseException;
import org.xbill.DNS.io.DefaultIoClientFactory;
import org.xbill.DNS.io.TcpIoClient;

/**
 * Provides DNS resolution for the shared CAA validator using dnsjava and a
 * trusted DNSSEC-validating resolver. This optional adapter keeps dnsjava types
 * and transport details out of the CAA policy engine and its public interfaces.
 *
 * Responsibilities:
 * - Resolve one CAA candidate, following CNAME and DNAME redirection as needed.
 * - Check that replies answer the requested question and contain usable CAA
 *   records or established absence, rather than a referral or conflicting data.
 * - Preserve complete CAA values, alias history, response observations and
 *   available negative-cache metadata in the shared result types.
 * - Leave parent discovery, issuer matching, wildcard rules and account/method
 *   binding to DefaultCAAValidator. This adapter does not authorize issuance.
 *
 * Resolver configuration:
 * - server is required and must be a numeric loopback address. Numeric addresses
 *   avoid a bootstrap lookup through the host's system DNS configuration.
 * - port is optional and defaults to 53. All queries use TCP to avoid UDP
 *   truncation and fallback handling in this adapter.
 * - Settings are fixed for each returned client. The operator supplies and
 *   configures the resolver separately; opening a client validates endpoint
 *   settings but does not prove that the resolver is enforcing DNSSEC correctly.
 *
 * DNSSEC trust contract:
 * - The resolver performs signature and chain-of-trust validation, maintains
 *   its trust anchors and withholds bogus answers. Local signature validation
 *   and trust-anchor management belong to the resolver, outside this adapter.
 * - AD-set replies are classified as SECURE under that trusted contract.
 *   AD-clear successful replies are UNCLASSIFIED and may be accepted; AD clear
 *   alone does not establish that a domain is unsigned.
 * - Resolver errors remain failures. Extended DNS Error information can refine
 *   a failure reason, but does not independently establish DNSSEC assurance.
 * - Loopback TCP does not authenticate the listening process. The host, network
 *   namespace, resolver configuration and access to that configuration form part
 *   of the deployment's trust boundary.
 *
 * Resource ownership and lifecycle:
 * - Each client supports concurrent lookups with separate per-query resolver
 *   settings. All exchanges and alias transitions consume the caller's shared
 *   lookup budget; following an alias does not reset its allowance or deadline.
 * - TCP framing bounds message size. The adapter caps parsed record counts and
 *   rejects excess concurrent transport work immediately instead of queuing it.
 * - Closing a client cancels waiting callers. An underlying TCP operation keeps
 *   its admission slot until completion, preventing cancelled callers from
 *   accumulating unbounded network work. dnsjava's shared transport stays open
 *   for other clients.
 */
public final class DNSJavaCAAProvider implements CAADNSClientProvider {
    private static final Set<String> CONFIGURATION_KEYS = Set.of("server", "port");
    private static final int MAX_RESPONSE_RECORDS = 1024;
    private static final int MAX_PENDING_QUERIES = 8;
    private static final int MAX_DIAGNOSTIC_LENGTH = 1024;

    /**
     * Creates a concurrently usable client for one trusted resolver endpoint.
     *
     * - Requires server as a numeric loopback address; port defaults to 53.
     *   Unknown settings, invalid addresses and invalid ports fail with CONFIGURATION.
     * - Fixes the settings for the returned client's lifetime. The consuming
     *   subsystem owns that client and closes it during shutdown or replacement.
     * - Sends no DNS queries during initialization. A successful open confirms
     *   valid endpoint settings, not resolver availability or correct DNSSEC policy.
     *   The operator must establish and maintain the enforcing-resolver contract.
     */
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

            if (!address.isLoopbackAddress()) {
                throw failure(DNSLookupException.Reason.CONFIGURATION,
                        "Delegated DNSSEC requires a loopback resolver address", List.of());
            }

            return new Client(new InetSocketAddress(address, port));
        } catch (IOException | IllegalArgumentException e) {
            throw failure(DNSLookupException.Reason.CONFIGURATION, "Invalid DNS adapter configuration", List.of(), e);
        }
    }

    /**
     * One immutable client configuration, with per-call resolver/deadline state.
     */
    private static final class Client implements CAADNSClient {
        private final InetSocketAddress server;
        private final AtomicBoolean closed = new AtomicBoolean();
        private final Set<CompletableFuture<Message>> pending = ConcurrentHashMap.newKeySet();
        // Hold each slot until its TCP operation completes, even if the caller
        // cancels. Otherwise interrupted requests could accumulate network work.
        private final Semaphore transportSlots = new Semaphore(MAX_PENDING_QUERIES);

        private Client(InetSocketAddress server) {
            this.server = server;
        }

        /**
         * Resolves one candidate through aliases; parent search stays in the engine.
         *
         * - candidate is the original absolute DNS name. The terminal name may
         *   differ after CNAME or DNAME traversal; both are retained in the result.
         * - Success returns the terminal CAA RRset, NODATA or NXDOMAIN, along with
         *   alias history, response observations and any enclosing SOA metadata.
         * - The caller supplies the shared budget. Every query and alias transition
         *   consumes it, including aliases followed within a single response.
         * - Lookup failures throw DNSLookupException with observations collected so
         *   far when available. Failed or incomplete lookups do not report absence.
         * - On absence, the engine decides whether to query the original candidate's
         *   parent. This method never climbs the terminal alias target's parents.
         *
         * Query candidate
         *       |
         *       +-- Relevant CAA --------> Return complete RRset
         *       |
         *       +-- Alias ---------------> Follow target in this answer
         *       |                          or query it in the next exchange
         *       |
         *       +-- Established absence -> Return NODATA or NXDOMAIN
         *       |
         *       +-- Conflict/referral ---> Fail; do not report absence
         */
        @Override
        public LookupResult resolveCaa(DNSDomainName candidate, LookupBudget budget) throws DNSLookupException {
            List<ResponseEvidence> evidence = new ArrayList<>();
            List<AliasStep> aliases = new ArrayList<>();
            Set<Name> visited = new HashSet<>();

            try {
                Name current = Name.fromString(candidate.asciiAbsoluteName());
                if (current.equals(Name.root)) {
                    throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE,
                            "Root CAA lookup is not supported", evidence);
                }

                // Keep candidate unchanged for the result. current moves through aliases;
                // the engine needs the original name when choosing the next parent.
                visited.add(current);
                while (true) {
                    checkOpen(evidence);

                    Message response = exchange(current, budget, evidence);
                    List<Record> answers = response.getSection(Section.ANSWER);
                    // Track records consumed from this reply separately from the full
                    // alias history, which may span several DNS exchanges.
                    Set<Record> aliasRecords = new HashSet<>();
                    boolean followed = false;

                    // Consume a complete alias chain from this answer before
                    // sending another query. visited spans every exchange.
                    while (true) {
                        // CAA and CNAME must belong to the name currently being resolved.
                        // DNAME is different: it can redirect from an enclosing owner.
                        Name owner = current;
                        List<Record> owned = answers.stream().filter(r -> r.getName().equals(owner)).toList();
                        if (owned.stream().anyMatch(r -> r.getDClass() != DClass.IN)) {
                            throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE,
                                    "Unexpected answer class", evidence);
                        }

                        List<org.xbill.DNS.CAARecord> caa = owned.stream()
                                .filter(r -> r instanceof org.xbill.DNS.CAARecord)
                                .map(r -> (org.xbill.DNS.CAARecord) r).toList();
                        List<CNAMERecord> cnames = owned.stream()
                                .filter(r -> r instanceof CNAMERecord)
                                .map(r -> (CNAMERecord) r).toList();
                        DNAMERecord dname = closestDname(answers, current, evidence);
                        // Terminal CAA must not conflict with an alias or NXDOMAIN.
                        // Return the full RRset; the shared engine evaluates its grants.
                        if (!caa.isEmpty()) {
                            if (!cnames.isEmpty() || dname != null || response.getRcode() != Rcode.NOERROR) {
                                throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE,
                                        "Conflicting terminal CAA data", evidence);
                            }

                            DNSDomainName terminal = domain(current);
                            List<CAADNSClient.CAARecord> records = caa.stream()
                                    .map(r -> new CAADNSClient.CAARecord(terminal, r.getTTL(),
                                            r.getFlags(), r.getTag(), r.getValueAsByteArray()))
                                    .toList();
                            return new LookupResult(candidate, terminal, LookupKind.RRSET, records,
                                    aliases, evidence, Optional.empty());
                        }

                        // Repeated CNAMEs may agree, but distinct targets make the
                        // redirect ambiguous. Never choose a target by answer order.
                        Set<Name> targets = new HashSet<>();
                        cnames.forEach(r -> targets.add(r.getTarget()));
                        if (targets.size() > 1) {
                            throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE,
                                    "Conflicting CNAME targets", evidence);
                        }

                        Name target = cnames.isEmpty() ? null : cnames.get(0).getTarget();
                        if (dname != null) {
                            // RFC 6672 Section 3.1: check any supplied CNAME
                            // against the target synthesized from the DNAME.
                            Name synthesized = current.fromDNAME(dname);
                            if (target != null && !target.equals(synthesized)) {
                                throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE,
                                        "Invalid DNAME synthesis", evidence);
                            }

                            target = synthesized;
                        }

                        if (target == null) {
                            break;
                        }

                        // Charge every alias transition, including those answered in this
                        // packet. Resolving without another query still consumes work.
                        budget.reserveAlias();
                        if (!visited.add(target)) {
                            throw failure(DNSLookupException.Reason.ALIAS_LOOP, "DNS alias loop", evidence);
                        }

                        long ttl = cnames.isEmpty() ? dname.getTTL() : cnames.get(0).getTTL();
                        if (dname != null) {
                            // RFC 6672 Section 3.1 ties the synthesized TTL to
                            // DNAME. Conservatively retain the smaller observed TTL.
                            ttl = Math.min(ttl, dname.getTTL());
                        }

                        aliasRecords.addAll(cnames);
                        if (dname != null) {
                            aliasRecords.add(dname);
                        }

                        aliases.add(new AliasStep(domain(current), domain(target),
                                dname == null ? AliasKind.CNAME : AliasKind.DNAME_SYNTHESIS, ttl));
                        current = target;
                        followed = true;
                    }

                    // RFC 2308 Sections 2.1-2.2: negative answers may retain
                    // the aliases just followed and their signatures. Reject
                    // other answer data before SOA or NXDOMAIN establishes absence.
                    for (Record answer : answers) {
                        if (aliasRecords.contains(answer)) {
                            continue;
                        }
                        if (isAliasSignature(answer, aliasRecords)) {
                            continue;
                        }

                        throw failure(DNSLookupException.Reason.INCOMPLETE_ANSWER,
                                "Unrelated answer is not CAA absence", evidence);
                    }

                    DNSDomainName terminal = domain(current);
                    List<Record> authority = response.getSection(Section.AUTHORITY);
                    SOARecord soa = closestNegativeSoa(authority, current, evidence);

                    // RFC 2308 Sections 2.1-2.2: classify absence at the terminal
                    // alias target. Parent discovery remains the engine's job.
                    LookupKind kind;
                    if (response.getRcode() == Rcode.NXDOMAIN) {
                        kind = LookupKind.NXDOMAIN;
                    } else if (soa != null) {
                        kind = LookupKind.NODATA;
                    } else if (authority.stream().anyMatch(r -> r.getType() == Type.NS)) {
                        // Delegation to another server is not a completed recursive
                        // lookup and cannot authorize moving on to a parent policy.
                        throw failure(DNSLookupException.Reason.INCOMPLETE_ANSWER, "Unresolved DNS referral", evidence);
                    } else if (followed) {
                        // An alias-only reply is not terminal absence. Query its target.
                        continue;
                    } else {
                        // A successful empty recursive answer can establish
                        // absence without supplying SOA negative-cache metadata.
                        kind = LookupKind.NODATA;
                    }

                    // Preserve negative-cache metadata when supplied. Absence is for
                    // terminal, while candidate tells the engine where this search began.
                    Optional<SOAEvidence> soaEvidence = soa == null ? Optional.empty()
                            : Optional.of(new SOAEvidence(domain(soa.getName()), soa.getTTL(), soa.getMinimum()));
                    return new LookupResult(candidate, terminal, kind, List.of(), aliases, evidence,
                            soaEvidence);
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
            }
        }

        /**
         * Recognizes signature metadata for an alias consumed from this answer.
         * The owner, class and covered type must all match. Signature validation
         * remains the enforcing resolver's responsibility.
         */
        private static boolean isAliasSignature(Record record, Set<Record> aliases) {
            if (!(record instanceof RRSIGRecord signature)) {
                return false;
            }

            for (Record alias : aliases) {
                if (alias.getName().equals(signature.getName())
                        && alias.getDClass() == signature.getDClass()
                        && alias.getType() == signature.getTypeCovered()) {
                    return true;
                }
            }

            return false;
        }

        /**
         * Performs one bounded TCP exchange and verifies response relevance.
         *
         * - Reserve query allowance and use the smaller remaining/query timeout.
         * - Hold a transport slot until the underlying TCP future completes.
         * - Track the caller's future separately so close() can cancel its wait.
         * - Check correlation, recursion, completeness and response limits before
         *   accepting data. Resolver errors always fail, including DNSSEC errors.
         *
         * Caller cancelled -> caller stops waiting
         *                         |
         *                         v
         * TCP still pending -> slot retained -> TCP completes -> slot released
         */
        private Message exchange(Name current, LookupBudget budget, List<ResponseEvidence> evidence)
                throws DNSLookupException, IOException {
            // Charge the attempt's shared query allowance before starting transport.
            // Following an alias must not reset this allowance or the total deadline.
            budget.reserveQuery();

            // Bound this query by both its timeout and the attempt's time left.
            Duration remaining = budget.remaining();
            Duration queryTimeout = budget.queryTimeout();
            Duration timeout = remaining.compareTo(queryTimeout) < 0 ? remaining : queryTimeout;
            if (timeout.isZero() || timeout.isNegative()) {
                throw failure(DNSLookupException.Reason.TIMEOUT, "CAA lookup deadline exceeded", evidence);
            }

            Message query = Message.newQuery(Record.newRecord(current, Type.CAA, DClass.IN));
            query.getHeader().setFlag(Flags.RD);

            // RFC 4035 Section 4.9.2: leave checking enabled when relying on
            // the recursive resolver to enforce DNSSEC.
            query.getHeader().unsetFlag(Flags.CD);

            // Keep timeout and I/O hooks local to this exchange so concurrent
            // lookups cannot overwrite one another's resolver settings.
            SimpleResolver resolver = new SimpleResolver(server);
            resolver.setTCP(true);
            resolver.setTimeout(timeout);

            // Request the resolver's AD classification and DNSSEC records (DO).
            // These flags request information; trust comes from the resolver contract.
            query.getHeader().setFlag(Flags.AD);
            resolver.setEDNS(0, 0, ExtendedFlags.DO);

            AtomicBoolean callerFinished = new AtomicBoolean();
            resolver.setIoClientFactory(new DefaultIoClientFactory() {
                @Override
                public TcpIoClient createOrGetTcpClient() {
                    TcpIoClient delegate = super.createOrGetTcpClient();
                    return (local, remote, message, bytes, allowance) -> {
                        if (closed.get() || callerFinished.get()) {
                            return CompletableFuture.failedFuture(failure(
                                    DNSLookupException.Reason.CANCELLED, "DNS query cancelled", List.of()));
                        }

                        // Admit work when TCP actually starts. Reject overload immediately
                        // instead of building a queue behind the shared transport.
                        if (!transportSlots.tryAcquire()) {
                            return CompletableFuture.failedFuture(failure(
                                    DNSLookupException.Reason.LIMIT_EXCEEDED,
                                    "DNS transport is at capacity", List.of()));
                        }

                        CompletableFuture<byte[]> transport;
                        try {
                            transport = delegate.sendAndReceiveTcp(local, remote, message, bytes, allowance);
                        } catch (RuntimeException | Error e) {
                            // No transport future was returned to release this reservation.
                            transportSlots.release();
                            throw e;
                        }

                        // Caller cancellation may leave TCP running. Release its slot
                        // only when that operation completes, successfully or otherwise.
                        transport.whenComplete((answer, error) -> transportSlots.release());

                        return transport;
                    };
                }
            });

            CompletableFuture<Message> future = resolver.sendAsync(query).toCompletableFuture();
            // close() cancels these caller futures, while TCP owns its slot separately.
            pending.add(future);
            try {
                // Cover close() racing with registration in pending: it may already
                // have scanned the set before this future was added.
                if (closed.get()) {
                    future.cancel(true);
                }

                Message response = future.get(timeout.toNanos(), TimeUnit.NANOSECONDS);
                // A reply arriving alongside shutdown or the attempt's deadline
                // must not turn a cancelled or expired lookup into success.
                checkOpen(evidence);
                if (budget.remaining().isZero()) {
                    throw failure(DNSLookupException.Reason.TIMEOUT, "CAA lookup deadline exceeded", evidence);
                }

                // Match the response to this exact question before retaining evidence
                // or interpreting its records as part of this lookup.
                if (!response.getHeader().getFlag(Flags.QR)
                        || response.getHeader().getID() != query.getHeader().getID()
                        || response.getHeader().getOpcode() != Opcode.QUERY
                        || response.getHeader().getCount(Section.QUESTION) != 1
                        || !query.getQuestion().equals(response.getQuestion())) {
                    throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE, "Mismatched DNS response", evidence);
                }

                // Retain correlated failures for diagnostics too. Truncation, missing
                // recursion support or disabled checking cannot establish CAA absence.
                evidence.add(observe(current, response));
                if (response.getHeader().getFlag(Flags.TC) || !response.getHeader().getFlag(Flags.RA)
                        || response.getHeader().getFlag(Flags.CD)) {
                    throw failure(DNSLookupException.Reason.INCOMPLETE_ANSWER,
                            "Incomplete or nonrecursive DNS response", evidence);
                }

                // Bound the total parsed records before resolving aliases or CAA
                // policy. Apply one limit across all three response sections.
                int count = response.getSection(Section.ANSWER).size()
                        + response.getSection(Section.AUTHORITY).size()
                        + response.getSection(Section.ADDITIONAL).size();
                if (count > MAX_RESPONSE_RECORDS) {
                    throw failure(DNSLookupException.Reason.LIMIT_EXCEEDED,
                            "DNS response record limit exceeded", evidence);
                }

                // Only success and NXDOMAIN can reach record/absence processing.
                // Other resolver errors must not trigger permissive parent discovery.
                if (response.getRcode() != Rcode.NOERROR && response.getRcode() != Rcode.NXDOMAIN) {
                    // RFC 8914 Sections 4.6-4.13 define DNSSEC error codes 5-12.
                    // Use these to refine an existing failure. Section 3 keeps
                    // RCODE handling unchanged; EDE cannot establish DNSSEC trust.
                    boolean validationFailure = response.getRcode() == Rcode.SERVFAIL
                            && response.getOPT() != null
                            && response.getOPT().getOptions().stream()
                                    .filter(ExtendedErrorCodeOption.class::isInstance)
                                    .map(ExtendedErrorCodeOption.class::cast)
                                    .anyMatch(error -> error.getErrorCode() >= 5 && error.getErrorCode() <= 12);
                    throw failure(validationFailure ? DNSLookupException.Reason.VALIDATION_FAILURE
                            : DNSLookupException.Reason.RCODE_FAILURE, "DNS resolver returned an error", evidence);
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
                // Stop any later transport start for this caller and remove its wait
                // from close() tracking. Cancelling this future does not free a TCP slot;
                // the underlying transport completion above owns that release.
                callerFinished.set(true);
                pending.remove(future);
                if (!future.isDone()) {
                    future.cancel(true);
                }
            }
        }

        /**
         * Maps the cause of an asynchronous exchange failure into a shared reason.
         * Preserve adapter failures, including transport admission refusals;
         * map dnsjava parsing failures to MALFORMED_RESPONSE and timeout causes to
         * TIMEOUT. Other causes fall back to UNREACHABLE. The caller retains the
         * original exception separately rather than exposing its text as the reason.
         */
        private static DNSLookupException.Reason exchangeFailureReason(Throwable cause) {
            if (cause instanceof DNSLookupException failure) {
                return failure.failure().reason();
            }

            if (cause instanceof WireParseException) {
                return DNSLookupException.Reason.MALFORMED_RESPONSE;
            }

            if (cause instanceof TimeoutException || cause instanceof SocketTimeoutException) {
                return DNSLookupException.Reason.TIMEOUT;
            }

            return DNSLookupException.Reason.UNREACHABLE;
        }

        /**
         * Classifies responses under the trusted enforcing-resolver contract.
         * AD distinguishes SECURE from UNCLASSIFIED; it does not establish the
         * trust relationship. EDE diagnostics do not independently establish
         * security or insecurity.
         */
        private ResponseEvidence observe(Name question, Message response) {
            boolean authenticatedData = response.getHeader().getFlag(Flags.AD);
            // RFC 4035 Section 4.9.3: AD is a resolver assertion, usable
            // only through our trusted enforcing-resolver contract.
            // AD clear does not prove that the zone is unsigned.
            ValidationStatus status = authenticatedData ? ValidationStatus.SECURE : ValidationStatus.UNCLASSIFIED;

            Optional<ExtendedError> diagnostic = Optional.empty();
            if (response.getOPT() != null) {
                diagnostic = response.getOPT().getOptions().stream()
                        .filter(ExtendedErrorCodeOption.class::isInstance)
                        .map(ExtendedErrorCodeOption.class::cast)
                        .findFirst().map(Client::extendedError);
            }

            return new ResponseEvidence(server.toString(), domain(question), response.getRcode(), authenticatedData,
                    status, "TCP", diagnostic);
        }

        /**
         * Resolver-supplied text is diagnostic only; bound and flatten it before retaining it.
         */
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

        /**
         * Marks this client closed and cancels its waiting caller futures.
         * Repeated calls are harmless; subsequent lookups fail with CANCELLED.
         *
         * This does not wait for underlying TCP operations to finish. They retain
         * their admission slots until completion or transport timeout. dnsjava owns
         * the shared transport, which must remain usable by other client instances.
         */
        @Override
        public void close() {
            closed.set(true);
            // Cancel waiting callers only. dnsjava owns its shared transport
            // and expires pending queries independently; never close its global
            // selector here, since other clients may still be using it.
            pending.forEach(future -> future.cancel(true));
        }
    }

    /**
     * Selects the DNAME with the most specific owner enclosing name from the
     * current answer section. RFC 6672 Section 2.3 limits DNAME to descendants:
     * an exact-owner DNAME and unrelated owners do not redirect this name.
     *
     * Returns null when no DNAME applies. Applicable records with the wrong DNS
     * class or conflicting targets detected during selection fail as
     * MALFORMED_RESPONSE, retaining the supplied response evidence. The caller
     * synthesizes the target and checks agreement with any accompanying CNAME.
     */
    private static DNAMERecord closestDname(List<Record> records, Name name, List<CAADNSClient.ResponseEvidence> evidence)
            throws DNSLookupException {
        DNAMERecord result = null;
        for (Record record : records) {
            if (!(record instanceof DNAMERecord dname)) {
                continue;
            }

            // Only strict ancestors redirect this name. A DNAME at the queried
            // owner applies to its descendants, leaving that owner's own CAA intact.
            if (!name.subdomain(dname.getName()) || name.equals(dname.getName())) {
                continue;
            }

            boolean conflictingTarget = result != null && result.getName().equals(dname.getName())
                    && !result.getTarget().equals(dname.getTarget());
            if (dname.getDClass() != DClass.IN || conflictingTarget) {
                throw failure(DNSLookupException.Reason.MALFORMED_RESPONSE, "Invalid or conflicting DNAME", evidence);
            }

            // Prefer the nearest enclosing owner rather than the first DNAME in
            // wire order. Its suffix is the one used to synthesize the target name.
            if (result == null || dname.getName().labels() > result.getName().labels()) {
                result = dname;
            }
        }

        return result;
    }

    /**
     * Selects SOA metadata for an answer establishing absence at terminal, which
     * may be an alias target in a different zone from the original candidate.
     *
     * Returns the most specific enclosing SOA, or null when none is supplied.
     * Any SOA with the wrong DNS class or an owner that does not enclose terminal
     * fails as INCOMPLETE_ANSWER, retaining the supplied response evidence.
     * The caller combines this metadata with the response code and answer data
     * to classify absence; this helper alone does not establish a negative result.
     */
    private static SOARecord closestNegativeSoa(List<Record> authority, Name terminal,
            List<CAADNSClient.ResponseEvidence> evidence) throws DNSLookupException {
        SOARecord closest = null;
        for (Record record : authority) {
            if (!(record instanceof SOARecord soa)) {
                continue;
            }

            // Negative evidence must enclose the terminal alias target. An SOA
            // for the original candidate's zone cannot prove absence elsewhere.
            if (soa.getDClass() != DClass.IN || !terminal.subdomain(soa.getName())) {
                throw failure(DNSLookupException.Reason.INCOMPLETE_ANSWER, "Unrelated negative SOA", evidence);
            }

            // Retain metadata from the closest enclosing zone when several SOAs
            // are present, independent of their order in the authority section.
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

    /**
     * Preserve the underlying cause without copying it into the public failure message.
     */
    private static DNSLookupException failure(DNSLookupException.Reason reason, String message,
            List<CAADNSClient.ResponseEvidence> evidence, Throwable cause) {
        DNSLookupException exception = failure(reason, message, evidence);
        exception.initCause(cause);
        return exception;
    }

}
