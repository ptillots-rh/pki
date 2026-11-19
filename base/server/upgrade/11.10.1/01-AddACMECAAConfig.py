# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import os

import pki.server.upgrade

logger = logging.getLogger(__name__)


class AddACMECAAConfig(pki.server.upgrade.PKIServerUpgradeScriptlet):
    """Add the CAA configuration template to existing ACME installations.

    Upgrade policy:
    - Leave non-ACME subsystems unchanged.
    - Preserve any existing destination, including administrator files and
      symbolic links whose targets no longer exist.
    - Copy the shipped enabled=false template only when the path is absent.

    The engine also treats a missing file as disabled. Adding this template
    does not enable CAA or require installation of an optional DNS provider.
    """

    def __init__(self):
        super().__init__()
        self.message = 'Add default-off ACME CAA configuration'

    def upgrade_subsystem(self, instance, subsystem):
        """Create a missing ACME policy using the standard instance copy helper.

        - Record the absent destination with the upgrade framework before
          copying, so rollback can remove a file created by this migration.
        - Use instance.copyfile() for normal ownership and permissions.
        - Propagate backup and copy failures instead of reporting a successful
          migration when the configuration could not be installed.
        """
        if subsystem.name != 'acme':
            return

        path = subsystem.caa_conf
        # lexists() also sees dangling symbolic links. Treat them as
        # administrator configuration rather than replacing their path.
        if os.path.lexists(path):
            return

        logger.info('Creating default-off ACME CAA configuration: %s', path)
        self.backup(path)
        instance.copyfile(
            os.path.join(pki.server.PKIServer.SHARE_DIR, 'acme', 'conf', 'caa.conf'),
            path)
