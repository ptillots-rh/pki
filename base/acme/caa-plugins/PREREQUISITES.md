# Prerequisites for reviewing and testing the CAA prototype

These instructions use only files in this checkout. They do not require a
particular container image. Run commands from the repository root.

dnsjava with delegated DNSSEC is the preferred product direction. The current
branch retains libunbound for prototype comparison; its presence here is not a
commitment to include it in the eventual product branch.

## Select the test layer

| Test layer | Software to install beforehand | Additional inputs or access |
| :-- | :-- | :-- |
| Shared CAA policy and gate | Full JDK 17 or newer and Maven 3 | Maven test dependencies/plugins, downloaded once or supplied in a cache |
| dnsjava adapter units | Above, plus Python 3.8 or newer for the documented tooling | Pinned PNC JAR/POM; internal repository access and approved HTTPS CA trust for the first download; loopback TCP permitted |
| libunbound adapter units | Above, plus a C11 compiler, pkg-config, libunbound development headers and runtime library | JNI headers from the JDK; build the bridge from this checkout; dnsjava is also required for test fixtures |
| Shared operational tests | Both adapters' prerequisites on Linux | Loopback TCP and access to process/thread/descriptor information |
| Private DNSSEC integration | Both adapters' prerequisites, Python, BIND with signing tools, and an Unbound daemon | Free loopback TCP/UDP ports 1053 and 1054; permission for daemons to read/write generated fixture files |
| Actual ACME-engine tests | Normal PKI Java build dependencies, including compatible JSS, LDAP SDK and Tomcat dependencies | Current upstream reactor requires JDK 21 or newer; compatible Maven artifacts must be available |
| Real enrollment | Installed CA-backed ACME service, database/realm, selected adapter and client/fixture tools | See the [enrollment guide](../../../tests/caa-plugin/enrollment/README.md); unit compilation alone does not install a working CA or plugin |

The default core and adapter units do not require a CA, Directory Server,
Certbot, a public DNS server, or public DNSSEC trust anchors. The Linux native
build script expects Linux JNI headers and produces a `.so` for the local
architecture. An Unbound daemon is not required for libunbound unit tests;
the library performs resolution/validation in process. The daemon is required
by the private DNSSEC fixture. In-process dnsjava needs the same Java dependency
as delegated dnsjava, plus an authenticated static DS/DNSKEY anchor file for
deployment. It needs neither JNI nor a validating daemon; the combined test
fixture still starts Unbound to compare delegated and local validation.

The libunbound production adapter does not depend on dnsjava. Its test suite
uses dnsjava to construct and sign fixture packets, which is why the documented
native test commands also select the pinned PNC artifact.

## Package examples

On Fedora, these install the tools for both adapter unit suites:

```sh
sudo dnf install java-devel maven python3 gcc pkgconf-pkg-config unbound-devel
```

For the private DNSSEC fixture, additionally install:

```sh
sudo dnf install bind bind-utils bind-dnssec-utils unbound
```

On Ubuntu 24.04, the corresponding examples are:

```sh
sudo apt-get install openjdk-17-jdk maven python3 gcc pkg-config libunbound-dev
sudo apt-get install bind9 bind9-utils unbound
```

JDK 17 is sufficient for standalone tests; select a newer JDK for the current
full PKI reactor. These are development examples, not an RHCS dependency
delivery or support declaration. On RHEL, provision the intended JDK, Python
and build tools from approved repositories. In particular, the native build
needs the development package, normally `unbound-devel`, as well as its matching
runtime library. A runtime library alone cannot compile the JNI bridge.
Qualify the exact RHEL package/API combination separately. RHEL 8's original
Python 3.6 is too old for the documented complete test tooling; use a separately
installed newer interpreter/environment without replacing platform Python.

Check the tools before starting:

```sh
java -version
javac -version
mvn -version
python3 --version
# Native adapter only:
cc --version
pkg-config --modversion libunbound
pkg-config --cflags --libs libunbound
# Private DNSSEC fixture only:
command -v named unbound dnssec-keygen dnssec-signzone dnssec-dsfromkey
```

Use a full JDK, not only a JRE. If `JAVA_HOME` is set, it must identify that
JDK so the native compiler can find `include/jni.h` and `include/linux/jni_md.h`.
The fixture processes use high ports and need no root privileges once tools
are installed. SELinux/AppArmor policy must permit their fixture directory;
the [test guide](../../../tests/caa-plugin/README.md#github-actions-coverage) describes those constraints.

## Prepare Maven and PNC inputs online

The helper downloads the selected dnsjava JAR and its POM from internal Indy,
checks their digests, and installs them in a separate Maven repository. It
does not install operating-system packages. Other dependencies and Maven
plugins use the normal Maven repository configuration. See the
[PNC guide](../../../tests/caa-plugin/pnc/README.md) for the build record, checksums and HTTPS trust setup.

For dnsjava-only review, run once with the required network access:

```sh
python3 tests/caa-plugin/pnc/pnc_dnsjava.py -- \
  -f tests/caa-plugin/pom.xml -Pdnsjava test
```

For both adapter unit suites, install the native prerequisites first, then run:

```sh
sh tests/caa-plugin/libunbound/build-native.sh
python3 tests/caa-plugin/pnc/pnc_dnsjava.py -- \
  -f tests/caa-plugin/pom.xml -Pdnsjava,libunbound test
```

Include any other profiles you intend to run offline, such as `operational` or
`dnssec-integration`, in an online preparation run. Those profiles can require
additional Maven inputs. To exercise ACME-engine tests, also prepare the normal
PKI build environment described in [Building PKI](../../../docs/development/Building_PKI.md)
and use the [engine test command](../../../tests/caa-plugin/README.md#run). The standalone cache alone
does not establish that the full PKI reactor is ready.

## Run offline after preparation

An offline build cannot download missing inputs. It needs all of the following:

- The exact pinned PNC JAR and POM under the helper's `inputs` directory.
- The helper's populated Maven repository, including its install plugin,
  dependency POMs, transitive dependencies, test libraries and build plugins.
- Installed JDK, Python and native tools/libraries for the chosen suites.
- BIND, signing utilities and Unbound if the DNSSEC fixture is selected.

The default helper cache is `~/.m2/pnc-dnsjava/BSHSPFWQYXIAA/`. Preserve the
whole directory, including `inputs/` and `repository/`, or supply a prepared
copy using `--cache-dir PATH`. A compatible cache can be prepared on another
connected machine and transferred through the approved process. The local
compiler/JDK/native packages must still be installed; transferring Maven files
does not supply them. Only copying a dnsjava JAR into the ordinary `~/.m2`
cache does not prepare this isolated build.

After an online run of the same profiles:

```sh
sh tests/caa-plugin/libunbound/build-native.sh
python3 tests/caa-plugin/pnc/pnc_dnsjava.py --offline -- \
  -f tests/caa-plugin/pom.xml -Pdnsjava,libunbound test
```

Rebuild JNI after a Maven `clean` removes its output. A changed dependency,
plugin version, JDK or profile may require another online preparation run.
Do not flush a working cache to solve a missing dependency: supply that input
or prepare again online. The helper rejects missing/mismatched PNC inputs
instead of substituting a Central artifact. A reviewer without internal access
needs an approved prepared input/cache; the checkout alone is insufficient.

The Java fixtures use local DNS traffic, so Maven's offline mode can be used
while allowing loopback sockets. Offline mode is not a prohibition on those
local sockets. Real enrollment has separate network and service requirements.

**Security-sensitive:** PNC input provenance, DNS trust and JNI require focused
review. Prepared caches and successful developer tests do not establish target
RHCS/RHEL support, FIPS qualification or public-TLS compliance.
