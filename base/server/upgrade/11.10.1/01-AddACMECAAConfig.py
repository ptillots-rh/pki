# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import os

import pki.server.upgrade

logger = logging.getLogger(__name__)


class AddACMECAAConfig(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Add default-off ACME CAA configuration'

    def upgrade_subsystem(self, instance, subsystem):
        if subsystem.name != 'acme':
            return

        path = subsystem.caa_conf
        # Preserve existing policy and links, including administrator changes.
        if os.path.lexists(path):
            return

        logger.info('Creating default-off ACME CAA configuration: %s', path)
        self.backup(path)
        instance.copyfile(
            os.path.join(pki.server.PKIServer.SHARE_DIR, 'acme', 'conf', 'caa.conf'),
            path)
