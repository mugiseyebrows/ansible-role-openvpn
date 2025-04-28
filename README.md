mugiseyebrows.openvpn
=====================

Ansible role to configure OpenVPN and manage client certificates

Install
-------

This role uses `ansible.posix` galaxy, so we need to install it too.

```bash
ansible-galaxy role install mugiseyebrows.openvpn
ansible-galaxy collection install ansible.posix --ignore-certs
```

Role Parameters
---------------

```yaml
# Should all client traffic go through vpn
reroute_all_traffic: false

# List of certificates to issue
issued: []

# List of certificates to revoke
revoked: []
```

Role Variables
---------------

```yaml
# Rsa variables
EASYRSA_REQ_COUNTRY:    US
EASYRSA_REQ_PROVINCE:   California
EASYRSA_REQ_CITY:       San Francisco
EASYRSA_REQ_ORG:        Copyleft Certificate Co
EASYRSA_REQ_EMAIL:      me@example.net
EASYRSA_REQ_OU:         My Organizational Unit

# OpenVPN variables
vpn_ip:                 10.8.0.0
vpn_mask:               255.255.255.0
ca_dir:                 /root/ca
```

Example Playbook
----------------

```yaml
---
- hosts: all
  gather_facts: yes
  roles:
  - name: mugiseyebrows.openvpn
    reroute_all_traffic: false
    issued: [bob, alice]
    revoked: []
```

To issue and revoke certificates edit parameters and rerun playbook. Issued certificates will be downloaded into current directory.

License
-------

MIT

Author Information
------------------

Doronin Stanislav <mugisbrows@gmail.com>
