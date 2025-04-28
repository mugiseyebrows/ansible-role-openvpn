mugiseyebrows.openvpn
=====================

Ansible role to configure OpenVPN and manage client certificates

Install
-------

```bash
ansible-galaxy role install mugiseyebrows.openvpn
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
  gather_facts: no
  roles:
  - name: mugiseyebrows.openvpn
    reroute_all_traffic: false
    issued: [bob, alice]
    revoked: []
```

To issue and revoke certificates edit parameters and rerun playbook

License
-------

MIT

Author Information
------------------

Doronin Stanislav <mugisbrows@gmail.com>
