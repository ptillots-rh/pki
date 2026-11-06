# CAA unit-test coverage

The suites below exercise the production CAA sources, configured DNS providers
and actual ACME issuance hook. The standalone sources compile as Java 17; the
current upstream ACME reactor uses Java 21.

**Security-sensitive:** issuance authorization, trusted context, DNS parsing,
plugin loading and JNI require extra review. This is a behavioral coverage map,
not a measured line/branch percentage or a product qualification claim.

## Suites

| Area | Test class | Tests | Behaviors covered |
| :-- | :-- | --: | :-- |
| Models and input contracts | [CAAContractsTest](acme/src/test/java/org/dogtagpki/acme/caa/CAAContractsTest.java) | 14 | Name/issuer validation, immutable data, contradictory decisions, alias connectivity and DNS assurance claims |
| Provider loading and ownership | [CAADNSClientLoaderTest](acme/src/test/java/org/dogtagpki/acme/caa/CAADNSClientLoaderTest.java) | 14 | Optional dependency absence, wrong SPI type without static initialization, constructors, null clients/behavior, linkage failures, cleanup ownership and preservation of the original failure |
| Discovery and CAA policy | [CAAIssuanceTest](acme/src/test/java/org/dogtagpki/acme/caa/CAAIssuanceTest.java) | 24 | Original-parent/TLD traversal, aliases, iodef, critical properties, additive grants, wildcard precedence, per-name binding, sibling reuse, all-name decisions, stale evidence, assurance, resource limits and shutdown |
| Issuance gate | [CAAIssuanceGateTest](acme/src/test/java/org/dogtagpki/acme/caa/CAAIssuanceGateTest.java) | 9 | Default-off behavior, rejected configuration, trimmed issuer lists, provider settings, audit-before-submit, audit/issuer errors, expiry and close-before-submit |
| Shared test budget | [CAALookupBudgetTest](acme/src/test/java/org/dogtagpki/acme/caa/CAALookupBudgetTest.java) | 2 | Test-fixture clock and allowances; the separate production budget is exercised by CAAIssuanceTest |
| dnsjava adapter | [DNSJavaCAAProviderTest](dnsjava/src/test/java/org/dogtagpki/acme/caa/dnsjava/DNSJavaCAAProviderTest.java) | 38 | TCP response correlation, binary CAA, CNAME/DNAME, negative answers/referrals, class/RCODE/flag errors, AD and delegated assurance, bounded EDE diagnostics, typed DNSSEC failures, in-process validator/anchor configuration, root priming, forged AD rejection, shared supporting-query budgets, deadlines/cancellation and concurrent response isolation |
| Native libunbound adapter | [LibUnboundCAAProviderTest](libunbound/src/test/java/org/dogtagpki/acme/caa/libunbound/LibUnboundCAAProviderTest.java) | 20 | Real JNI calls, signed and bogus records, tampered grants blocked at the gate, authenticated unsigned delegation, signed absence, unusable/wrong anchors, managed-state rejection, anchor snapshots, signature times, forged AD, cancellation and concurrent contexts |
| Detached native evidence | [UnboundCAAResponseTest](libunbound/src/test/java/org/dogtagpki/acme/caa/libunbound/UnboundCAAResponseTest.java) | 9 | Restrictive-record omission/duplicate substitution, canonical-name mismatch, unrelated SOA/referrals, compression loops, oversized counts, trailing bytes, invalid DNAME synthesis, TTL caps and copied native buffers |
| Actual ACME host | [ACMEEngineCAATest](../../base/acme/src/test/java/org/dogtagpki/acme/server/ACMEEngineCAATest.java) | 22 | CSR-before-DNS-before-issuer ordering, real CSR/context mapping through the ACME adapter, account/name/wildcard ownership, expired/pending/foreign authorization, valid challenge timestamps, duplicate/ambiguous methods, disabled/failed initialization, configuration I/O errors, persisted errors, shutdown and CA submission failure |
| Shared operational workload | [CAAOperationalTest](operational/src/test/java/org/dogtagpki/acme/caa/CAAOperationalTest.java) | 4 | Both plugins: repeated timeouts, descriptor/JVM-thread/OS-thread bounds, eight-check admission, rejection of excess work, close/interruption and recovery |

The standalone total is 130 tests. The actual ACME engine adds 22, for 152
Java unit tests. Several methods exercise a
matrix of input variants; the counts above are executed test methods, not
inflated per-variant counts. The default core suite has no dnsjava/native
runtime dependency. The gate and detached packet reader have separate suites.

The loader substitution test uses the real DefaultCAAValidator. The ACME host
tests use a recording issuer so a denial or DNS failure can be checked for zero
issuer calls. Both CSR fixtures contain only public requests. The single-name
request exercises actual extraction and authorization-context mapping through
the engine's CAA adapter; the other checks CN and two DNS SANs. Tests parse
without signature verification; existing CSR validation remains a separate
stage. The test driver invokes CSR validation, CAA validation and the issuer,
matching the servlet's sequence without executing the HTTP/JWS handler.
No production context factory is
overridden by the issuance tests.

The native signature-time tests place invalid signatures beyond libunbound's
clock-skew allowance. They do not assert zero tolerance or silently change the
validator's timestamp policy. See the
[Unbound clock-skew settings](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html).

## Run

The [test guide](README.md#run) provides Maven commands and native prerequisites
for the standalone adapters and actual ACME engine suite. The latter requires
the normal PKI Java build dependencies. Adapter tests use bounded loopback TCP
fixtures; they do not deploy a CA, issue certificates or use public DNS.
The default core runs independently:

```bash
mvn -B -f tests/caa-plugin/pom.xml test
```

## Functional coverage and remaining work

The retained [GitHub workflow](../../.github/workflows/acme-caa-test.yml) defines eight
private-hierarchy DNSSEC integration tests. Six exercise delegated dnsjava,
in-process dnsjava and embedded libunbound through the issuance gate. Two more
check local dnsjava root-anchor failure and static DNSKEY snapshots. Secure grants/denials, a tampered signed grant, established
insecurity, signed alias/negative discovery and outages are covered. These add
eight executed methods to the 152 core/adapter/engine tests and four operational
tests, for 164 total. Unlike the
native packet fixtures, these use real BIND and standalone Unbound daemons.
The [test README](README.md#github-actions-coverage) describes the job matrix,
dependencies, commands and limits.

CAA-specific GitHub jobs are currently disabled while the PNC artifact requires
internal access. Local prototype runs use the [PNC helper](pnc/README.md).
Its ten Python checks cover input verification, no-network cached operation,
download failure/size limits, isolation and rejection of a different installed
artifact. These are separate from the 19 migration/harness/order-verifier checks.

The [portable enrollment suite](enrollment/README.md) exercises actual HTTP/JWS
finalization and CA issuance for both plugins, with exact final-name checks and
authenticated retrieval of stored order status/error state. Its upgrade option
tests real migration helpers, rollback and the upgrade command followed by
restart. The disabled ACME CAA job defines this as a separate basic-workflow
variant with test-only plugin artifacts. Eight migration unit checks and eleven
harness/order-verifier checks are counted separately from the Java suites.

These units do not establish CA route exclusivity, final certificate-name
preservation, freshness across remote signing queues, exact RHEL/RHCS runtime
or RPM/upgrade behavior, FIPS qualification, native memory safety under tooling,
public root-anchor rollover, or sustained-load behavior. Malformed packet
fixtures and concurrent calls are useful checks, not substitutes for fuzzing,
native memory/race tools and deployment testing. Reactor success in other
modules is dependency compilation; the runner selects only ACMEEngineCAATest
for execution there.
