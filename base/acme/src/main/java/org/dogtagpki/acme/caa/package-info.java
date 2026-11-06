// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

/**
 * Reusable CAA policy engine and explicitly configured DNS plugins for ACME.
 *
 * Security-sensitive: these types model issuance authorization and DNS trust.
 * The optional dnsjava and libunbound adapters live in separate source
 * modules, outside the ACME core artifact. Deployment requires extra
 * security and standards review before enabling issuance enforcement.
 *
 * Record compact constructors validate their parameters and replace mutable
 * collections with immutable copies. Java assigns those parameters to the
 * record fields when the compact constructor completes successfully.
 */
package org.dogtagpki.acme.caa;
