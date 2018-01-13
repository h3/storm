# -*- coding: utf-8 -*-

from os import makedirs
from os import chmod
from os.path import dirname
from os.path import expanduser
from os.path import exists
from operator import itemgetter
import re

import six


class AuthorizedKeys(object):
    """
    Example: https://www.ibm.com/support/knowledgecenter/en/SSLTBW_2.3.0/com.ibm.zos.v2r3.foto100/authkeyf.htm
    # Comments allowed at start of line
    ssh-rsa AAAAB3Nza...LiPk== user@example.net
    from="*.sales.example.net,!pc.sales.example.net" ssh-rsa AAAAB2...19Q== john@example.net
    command="dump /home",no-pty,no-port-forwarding ssh-dss AAAAC3...51R== example.net
    permitopen="192.0.2.1:80",permitopen="192.0.2.2:25" ssh-dss AAAAB5...21S==
    ssh-rsa AAAA...==jane@example.net
    zos-key-ring-label="KeyRingOwner/SSHAuthKeysRing uniq-ssh-rsa"
    from="*.example.com",zos-key-ring-label="KeyRingOwner/SSHAuthKeysRing uniq-ssh-dsa"
    """  # noqa
    _from = None
    cert_authority = False
    command = None
    environment = {}
    no_X11_forwarding = False
    no_agent_forwarding = False
    no_port_forwarding = False
    no_pty = False
    no_user_rc = False
    permitopen = {}
    principals = None
    tunnel = 'n'
    zos_key_ring_label = {}


class AuthorizedKeysParser(object):
    """
    Parser for ~/.ssh/authorized_keys files.
    """

    def __init__(self, ssh_authorized_keys=None):
        if not ssh_authorized_keys:
            ssh_authorized_keys = self.get_default_authorized_keys()

        self.defaults = {}

        self.ssh_authorized_keys = ssh_authorized_keys

        if not exists(self.ssh_authorized_keys):
            if not exists(dirname(self.ssh_authorized_keys)):
                makedirs(dirname(self.ssh_authorized_keys))
            open(self.ssh_authorized_keys, 'w+').close()
            chmod(self.ssh_authorized_keys, 0o600)

        self.data = []

    def get_default_authorized_keys(self):
        return expanduser("~/.ssh/authorized_keys")

    def parse(self, fd):
        for cnt, line in enumerate(fd):
            self.data.append(line)

    def load(self):
        config = AuthorizedKeys()

        with open(self.ssh_authorized_keys) as fd:
            self.parse(fd)

        return self.data

    def add_key(self, key, options):
        self.data.append({
            'key': key,
            'options': options,
            'order': self.get_last_index(),
        })

        return self

    def update_key(self, host, options, use_regex=False):
        for index, host_entry in enumerate(self.data):
            if host_entry.get("host") == host or \
                    (use_regex and re.match(host, host_entry.get("host"))):

                if 'deleted_fields' in options:
                    deleted_fields = options.pop("deleted_fields")
                    for deleted_field in deleted_fields:
                        del self.data[index]["options"][deleted_field]

                self.data[index]["options"].update(options)

        return self

    def search_key(self, search_string):
        results = []
        for host_entry in self.data:
            if host_entry.get("type") != 'entry':
                continue
            if host_entry.get("host") == "*":
                continue

            searchable_information = host_entry.get("host")
            for key, value in six.iteritems(host_entry.get("options")):
                if isinstance(value, list):
                    value = " ".join(value)
                if isinstance(value, int):
                    value = str(value)

                searchable_information += " " + value

            if search_string in searchable_information:
                results.append(host_entry)

        return results

    def delete_key(self, host):
        found = 0
        for index, host_entry in enumerate(self.data):
            if host_entry.get("host") == host:
                del self.data[index]
                found += 1

        if found == 0:
            raise ValueError('No host found')
        return self

    def delete_all_keys(self):
        self.data = []
        self.write_to_authorized_keys()

        return self

    def dump(self):
        if len(self.data) < 1:
            return

        file_content = ""
        self.data = sorted(self.data, key=itemgetter("order"))

        return file_content

    def write_to_authorized_keys(self):
        with open(self.ssh_authorized_keys, 'w+') as f:
            data = self.dump()
            if data:
                f.write(data)
        return self

    def get_last_index(self):
        last_index = 0
        indexes = []
        for item in self.data:
            if item.get("order"):
                indexes.append(item.get("order"))
        if len(indexes) > 0:
            last_index = max(indexes)

        return last_index
