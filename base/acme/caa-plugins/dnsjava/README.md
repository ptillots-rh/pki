# Optional ACME dnsjava CAA adapter

This module implements the DNS provider SPI in `org.dogtagpki.acme.caa`.
CAA policy/interfaces live in `base/acme`; the adapter lives here so ACME can
build and run without dnsjava. The dependency points from this module to
`pki-acme`, never from ACME core to this module.

**Security-sensitive:** DNS parsing and trust interpretation affect issuance
authorization. Extra security and standards review is required. The adapter is wired to the ACME CAA engine and issuance gate. Deployment
and supported dependency delivery still require qualification.

## Build selection

The adapter is omitted by default. Enable it through the build path in use:

- Maven: profile `acme-dnsjava`, for example
  `python3 tests/caa-plugin/pnc/pnc_dnsjava.py -- -Pacme-dnsjava -pl base/acme/caa-plugins/dnsjava -am package`.
- CMake: `-DWITH_ACME_DNSJAVA=ON`, with `WITH_ACME=ON`.
  `DNSJAVA_JAR` can supply an explicit absolute library path; otherwise the
  module checks standard Java locations and XMvn resolution.
- Build script: `./build.sh --with-acme-dnsjava dist` or
  `./build.sh --with-acme-dnsjava rpm`.
- RPM: `--with acme_dnsjava`. This enables the Maven module, CMake installation,
  ACME webapp links, and conditional build/runtime dependency on
  `mvn(dnsjava:dnsjava) >= 3.6.5`. The adapter is included in the ACME package.

An enabled build produces `pki-acme-dnsjava.jar` and installs it alongside
`pki-acme.jar`. Conditional links place the adapter and installed dnsjava JAR
on the ACME webapp classpath. This module does not bundle dnsjava. Disabled
builds perform no dnsjava lookup or adapter installation.

Local prototype builds select the JAR from PNC build `BSHSPFWQYXIAA` through
the [PNC build helper](../../../../tests/caa-plugin/pnc/README.md). It checks
the JAR/POM digests and installs the actual artifact into a separate Maven
cache. Its coordinates remain `dnsjava:dnsjava:3.6.5`, so adding a repository
alone would not distinguish it from a previously cached Central binary.
The POM itself remains usable for community builds with normal Maven
resolution. Use the helper to select PNC explicitly; it does not compile
dnsjava from source. CAA-specific GitHub jobs are temporarily disabled.

The RPM path currently requires an installed Maven-capability provider. Using
an approved imported/bundled upstream JAR instead would require corresponding
build and packaging changes. Fedora publishing is one possible delivery route,
not a requirement for obtaining or using the library. The build inputs/runtime
dependency still need approved RHEL delivery and a maintenance owner. Build wiring is not product qualification. Java source remains
compatible with Java 17; the current upstream build uses its own newer baseline.

## Provider classes and tests

The [shared prerequisites](../PREREQUISITES.md) explain
what reviewers must install and cache before online or offline testing.

`org.dogtagpki.acme.caa.dnsjava.DNSJavaCAAProvider` has fixed unchecked behavior.
Its nested `$LocalValidatingResolver` variant uses a loopback enforcing resolver;
selecting it does not establish the resolver's configuration or anchor health.
Both accept only `server` and `port`. The nested `$Validating` variant performs
in-process DNSSEC validation and additionally requires `trustAnchors`.
There is no configurable validation mode; selecting the provider fixes behavior.

The adapter follows aliases and produces DNS evidence; it does not search
parents or decide CAA authorization. Installing the JAR does not enable an
issuance control or register CAA as a domain-control challenge.

Tests remain in `tests/caa-plugin`. Its optional `-Pdnsjava` profile compiles this
production source directly and exercises local TCP fixtures without needing the
full PKI dependency graph. See the standalone test README for commands and limits.

## ACME configuration

See the [plugin guide](../README.md#acme-configuration) for
`caa.conf`, issuance behavior, build combinations and verification commands.
The default provider is for Phase 1 without DNSSEC assurance. The nested
`LocalValidatingResolver` requires an operator-managed enforcing loopback
resolver; it does not configure, deploy or continuously verify that service.

## DNSSEC and tests

The adapter offers two DNSSEC paths: delegation to a trusted enforcing loopback
resolver, or dnsjava's built-in `ValidatingResolver` inside the ACME JVM.
They use the same CAA policy engine and result interface. Neither falls back to
an unchecked provider if validation fails.

### In-process dnsjava validation

Select the following in the instance's `caa.conf`:

```properties
enabled=true
issuerIdentifiers=ca.example.com
dns.class=org.dogtagpki.acme.caa.dnsjava.DNSJavaCAAProvider$Validating
dns.settings.server=127.0.0.1
dns.settings.port=53
dns.settings.trustAnchors=/etc/pki/pki-tomcat/acme/caa-trust-anchors.key
```

The numeric endpoint supplies DNS answers and DNSSEC proofs over TCP. Normally
it is a recursive resolver; it need not perform validation, and the adapter does
not trust its AD flag. A separate validating daemon and JNI are not required.
The library performs signature and chain validation in the ACME process.

Provide an authenticated static export containing explicit, single-line IN DS
or DNSKEY records. These are DNSSEC anchors, not X.509 certificates. The adapter
rejects empty, malformed, oversized and recognized RFC 5011 managed-state files.
It snapshots the configured records at initialization and does not inherit
trust anchors from JVM properties. Updating the file requires a full PKI/Tomcat
restart. An operational owner must handle bootstrap, rollover, monitoring and
recovery; automatic RFC 5011 updates and hot reload are not implemented.

With a root anchor, each candidate lookup first establishes root trust. A
successful local validation can then report secure data or established
insecurity. Incorrect root anchors block both signed and unsigned issuance.
With zone-only anchors, only secure results are accepted; AD-clear responses
cannot authorize issuance outside their coverage.

Each candidate lookup gets a fresh validating resolver and key cache. Supporting
DNSKEY/DS requests consume the shared query budget and deadlines. Cancellation
stops pending exchanges and subsequent DNS requests. There is no persistent
cross-candidate validation cache. Validation CPU costs, sustained load, rollover
and exact target cryptographic-provider/FIPS behavior still need qualification.
See the upstream [dnsjava DNSSEC documentation](https://github.com/dnsjava/dnsjava#dnssec).

### Delegated validation

Select `DNSJavaCAAProvider$LocalValidatingResolver` in the deployed `caa.conf`
for delegated DNSSEC. It requires the explicit loopback DNS endpoint of an
operator-managed validating resolver. That resolver owns the DNS root anchors,
validation policy and rollover. The Java adapter sends RD/DO with CD clear,
preserves AD and response evidence, and refuses failed DNS answers without
falling back to an unchecked resolver. An AD-clear success remains
`UNCLASSIFIED`; it does not independently prove that a domain is unsigned.

If a failing SERVFAIL response carries an RFC 8914 DNSSEC error (codes 5-12),
the adapter reports `VALIDATION_FAILURE`. SERVFAIL without that diagnostic
remains `RCODE_FAILURE`. EDE only refines an already failing result; it does not
change RCODE handling or provide authentication. See
[RFC 8914](https://www.rfc-editor.org/rfc/rfc8914.html).

The [DNSSEC integration tests](../../../../tests/caa-plugin/README.md#github-actions-coverage)
start an isolated BIND authority and validating Unbound with a generated private
trust anchor. They check secure grants/denials, tampered signatures, authenticated
unsigned delegation, signed alias/negative answers and outages through the real
CAA gate. They do not deploy ACME or enroll certificates. Signing tools and BIND
are test dependencies, not dependencies of this production adapter.
The same scenarios also exercise in-process dnsjava against the authoritative
fixture with a private root anchor. Additional cases cover wrong root anchors
and DNSKEY anchor snapshots. The portable enrollment harness offers
`--dnssec --provider dnsjava-local` for real ACME finalization and CA issuance.
