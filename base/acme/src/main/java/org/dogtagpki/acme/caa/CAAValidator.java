// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

/** Evaluates CAA authorization for all names in one issuance attempt. */
public interface CAAValidator {
    CAADecision validate(CAARequest request);
}
