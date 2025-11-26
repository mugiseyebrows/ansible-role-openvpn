from ansible.module_utils.basic import AnsibleModule

from ansible.module_utils.openvpnutils import read_index, is_legacy_ca, source_vars

import re
import os
from subprocess import PIPE, Popen, check_output
from dataclasses import dataclass
import zipfile

def read_file(name):
    cwd = os.getcwd()
    path = os.path.join(cwd, name)
    with open(path, encoding='utf-8') as f:
        return f.read()

@dataclass
class Args:
    server: str = None
    ca: str = None
    ta: str = None
    cert: str = None
    key: str = None

def create_ovpn(args: Args, output: str):
    cert_path = args.cert
    key_path = args.key
    ca = read_file(args.ca)
    ta = read_file(args.ta)
    cert = read_file(cert_path)
    key = read_file(key_path)
    with open(output, "w", encoding='utf-8') as f:
        print(f"""client
dev tun
remote {args.server}
<ca>
{ca}
</ca>
<cert>
{cert}
</cert>
<key>
{key}
</key>
<tls-auth>
{ta}
</tls-auth>
key-direction 1
""", file = f)

def create_zip(args: Args, output: str):
    cert_path = args.cert
    key_path = args.key
    name = os.path.splitext(os.path.basename(cert_path))[0]
    conf_path = f"{name}.conf"
    with open(conf_path, "w", encoding='utf-8') as f:
        print(f"""client
dev tun
remote {args.server}
ca ca.crt
cert {os.path.basename(cert_path)}
key {os.path.basename(key_path)}
tls-auth ta.key 1
""", file = f)
    if os.path.exists(output):
        os.remove(output)
    with zipfile.ZipFile(output, 'w') as z:
        for path in [conf_path, args.ca, args.ta, cert_path, key_path]:
            z.write(path, arcname=os.path.basename(path))
    os.remove(conf_path)


def issue(client, params, res):

    ca_dir = params['ca_dir']

    def ca_path(*args):
        return os.path.join(ca_dir, *args)
    
    if not os.path.exists(ca_path('pki')):
        res['errors'].append({'error':'pki dir not found, legacy easyrsa ca?'})
        return

    proc = Popen(['easyrsa', '--batch', 'build-client-full', client, 'nopass'], stderr=PIPE, stdout=PIPE, cwd=ca_dir)

    stdout, stderr = proc.communicate()

    if proc.returncode != 0:
        res['errors'].append({
            'client': client,
            'stdout': stdout,
            'stderr': stderr
        })
        return

    args = Args(
        server=params['server'],
        ca=ca_path('pki/ca.crt'),
        ta=ca_path('pki/private/ta.key'),
        cert=ca_path(f'pki/issued/{client}.crt'),
        key=ca_path(f'pki/private/{client}.key'),
    )

    os.makedirs(ca_path('pki/tmp'), exist_ok=True)
    ovpn_path = ca_path(f'pki/tmp/{client}.ovpn')
    zip_path = ca_path(f'pki/tmp/{client}.zip')
    create_ovpn(args, ovpn_path)
    create_zip(args, zip_path)

    res['changed'] = True
    res['files'].append(ovpn_path)
    res['files'].append(zip_path)
    res['issued'].append(client)

def issue_legacy(client, params, res):
    ca_dir = params['ca_dir']
    def ca_path(*args):
        return os.path.join(ca_dir, *args)
    
    #res['debug'].append(env)

    try:
        env = source_vars(ca_dir)
    except ValueError as e:
        res['errors'].append(str(e))
        return
    
    proc = Popen(['./pkitool', client], stderr=PIPE, stdout=PIPE, cwd=ca_dir, env=env)
    stdout, stderr = proc.communicate()

    if proc.returncode != 0:
        res['debug'].append({'client': client, 'stdout': stdout, 'stderr': stderr, 'returncode': proc.returncode})
        return

    #res['debug'].append({'client': client, 'stdout': stdout, 'stderr': stderr, 'returncode': proc.returncode})
 
    args = Args(
        server=params['server'],
        ca=ca_path('keys/ca.crt'),
        ta=ca_path('keys/ta.key'),
        cert=ca_path(f'keys/{client}.crt'),
        key=ca_path(f'keys/{client}.key'),
    )

    os.makedirs(ca_path('keys/tmp'), exist_ok=True)
    ovpn_path = ca_path(f'keys/tmp/{client}.ovpn')
    zip_path = ca_path(f'keys/tmp/{client}.zip')
    create_ovpn(args, ovpn_path)
    create_zip(args, zip_path)

    res['changed'] = True
    res['files'].append(ovpn_path)
    res['files'].append(zip_path)
    res['issued'].append(client)

def main():
    module = AnsibleModule(
        argument_spec=dict(
            issued=dict(type='list', elements='str'),
            ca_dir=dict(type='str'),
            server=dict(type='str'),
        )
    )
    params = module.params
    clients = params['issued']
    ca_dir = params['ca_dir']

    def ca_path(*args):
        return os.path.join(ca_dir, *args)

    res = {
        'changed': False,
        'issued': [],
        'files': [],
        'errors': [],
        'debug': []
    }

    issued, revoked = read_index(ca_dir)

    #res['debug'].append({"issued": issued, "revoked": revoked})

    legacy_ca = is_legacy_ca(ca_dir, res)

    if legacy_ca:
        issue_fn = issue_legacy
    else:
        issue_fn = issue

    for client in clients:
        if client not in issued:
            issue_fn(client, params, res)
    
    module.exit_json(**res)

if __name__ == "__main__":
    main()