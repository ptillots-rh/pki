# Optional ACME libunbound CAA adapter

This module implements `CAADNSClientProvider` without dnsjava. ACME core owns
CAA discovery and policy; libunbound handles DNS resolution, transport, aliases
and optional cryptographic DNSSEC validation. No Unbound daemon is required.

**Security-sensitive:** JNI, untrusted DNS parsing and issuance authorization
require extra review. This is implemented integration for development and
review, not a qualified RHCS release.

## Build and delivery

For review from a checkout, follow the [shared prerequisites](../PREREQUISITES.md).
They distinguish native development/runtime packages, test-only dnsjava input,
and the additional daemons needed for private DNSSEC fixtures. libunbound
remains a comparison prototype on this branch; its presence does not commit
the product branch to shipping it.

The module is off by default and independent of the dnsjava build flag.

- Maven: `-Pacme-libunbound` includes the Java adapter. Maven alone does not
  compile or install JNI. The normal PKI CMake build supplies the native library.
- CMake: `-DWITH_ACME_LIBUNBOUND=ON`, with ACME enabled. Requires JNI headers,
  a C compiler and `pkg-config libunbound` (normally `unbound-devel`).
- Build script: `./build.sh --with-acme-libunbound dist` or `rpm`.
- RPM: `--with acme_libunbound` creates the architecture-specific
  `pki-acme-libunbound` subpackage (product prefix may differ). It contains
  the adapter JAR, webapp link and `libpki_acme_unbound.so`; the linked system
  libunbound supplies its normal ELF runtime dependency.

`System.loadLibrary("pki_acme_unbound")` uses the JVM's native search path.
The RPM installs the bridge in the platform library directory. A manual
installation must make that directory available at JVM startup. No library
path supplied by an enrollment request is accepted. Disabled CAA never loads JNI.
Missing/incompatible native delivery blocks enabled CAA at initialization.

## Configuration

Configure `<instance>/conf/acme/caa.conf` and restart the PKI/Tomcat instance:

```properties
# Phase 1: DNS resolution without DNSSEC assurance.
enabled=true
issuerIdentifiers=ca.example.com
dns.class=org.dogtagpki.acme.caa.libunbound.LibUnboundCAAProvider
dns.settings.server=127.0.0.1
dns.settings.port=53
```

For local DNSSEC validation, select the fixed validating class instead:

```properties
dns.class=org.dogtagpki.acme.caa.libunbound.LibUnboundCAAProvider$Validating
dns.settings.trustAnchors=/etc/pki/pki-tomcat/acme/caa-trust-anchors.key
```

The validating provider requires a nonempty, bounded ASCII file of explicit,
single-line `IN DS` or `IN DNSKEY` records, with optional TTLs and comments.
It checks record encoding at startup; libunbound checks cryptographic validity
on lookup. With root anchors, each native context first validates the root
DNSKEY RRset within the same lookup deadline. A configured but ineffective
root anchor cannot make every answer appear acceptably insecure.
A usable root anchor permits secure and proven-insecure outcomes. With
only zone anchors, nonsecure answers are refused because trust coverage might
have been left by an alias. Bogus data and resolution errors always block.
These anchors are DNS keys, not X.509 certificates or NSS trust certificates.

Signature-time validation currently inherits libunbound's clock-skew defaults;
it is not a zero-tolerance timestamp check. Unit tests use expired/future
signatures outside that allowance. See the
[Unbound clock-skew settings](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html).

RFC 5011 managed-state files are rejected: their comments identify pending or
revoked keys, and treating every listed record as trusted would lose those
states. An external updater must export only currently trusted records to the
static file. Do not point this setting directly at a managed `root.key` file.

Anchors are snapshotted on open. An external owner must bootstrap and update
the file and restart the PKI/Tomcat instance after changes. This adapter does not use
`ub_ctx_add_ta_autr`, implement RFC 5011 rollover, or provide an updater.
Do not give ACME write permission merely to read an externally maintained file.
A supported Phase 2 deployment still needs an anchor lifecycle/recovery plan,
exact RHEL algorithm/API qualification and applicable FIPS review.

## Boundary and limits

Each lookup owns a private native context and worker. The bridge uses
`ub_resolve_async`, polls for completion/cancellation and frees the context and
result before returning. Closing the client cancels pending native waits without
interrupting unrelated servlet work. No native pointers escape into Java.
There is no shared cache between checks. This simple lifetime model trades
performance for isolated per-call ownership; measure it under realistic load.

The configured numeric forwarder is explicit. The adapter does not read
`resolv.conf`, `/etc/hosts`, a daemon configuration, or shell-command output.
It uses TCP to that forwarder; validation queries may cause multiple DNS
exchanges inside libunbound. The shared query allowance counts API lookups;
the monotonic timeout also bounds the native resolution wait. Initialization,
result copying and native teardown still need worst-case timing qualification.
The native library's built-in reserved local zones are retained.

A bounded evidence reader inspects libunbound's completed binary answer packet
for connected CNAME/DNAME transitions, terminal CAA RDATA and negative SOA
metadata, and cross-checks it against `ub_result`. This is additional maintained
code compared with the dnsjava adapter. Unsupported/mismatched/incomplete
results fail closed. The reader performs no network I/O or DNSSEC cryptography.

See the [plugin guide](../README.md#issuance-behavior) for the issuer gate and
deployment requirements, and the [test guide](../../../../tests/caa-plugin/README.md)
for commands and test limits.

References: [libunbound API](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/libunbound.html),
[RFC 8659](https://www.rfc-editor.org/rfc/rfc8659.html).

The current JNI placement assumes one ACME webapp class loader per JVM. Multiple
ACME contexts or hot redeployment need separate qualification because a native
library cannot be loaded independently into several webapp class loaders.
Use a full PKI/Tomcat restart for native-library or anchor configuration changes.

## DNSSEC tests

The local validating provider is the nested
`LibUnboundCAAProvider$Validating` class. It uses the same resolver SPI as the
unchecked provider; no extra validation-mode setting is needed. The operator
supplies the static anchor file described above. A usable root anchor permits
secure data and authenticated insecurity; failed validation and unavailable
validation prerequisites block issuance.

The [DNSSEC integration tests](../../../../tests/caa-plugin/README.md#github-actions-coverage)
build the JNI bridge and run the real provider against a private signed
hierarchy. The native client forwards directly to a nonvalidating BIND authority
on loopback port 1054. libunbound performs the cryptographic checks; it does not
consume a daemon's AD flag. A separate test Unbound resolver checks private-root
readiness but is not in the native issuance lookup path. Generated anchors are
test data, not public root keys. These tests exercise the CAA gate without
deploying ACME or enrolling certificates.
