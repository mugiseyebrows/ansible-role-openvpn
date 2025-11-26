from ansible.module_utils.basic import AnsibleModule

from ansible.module_utils.openvpn import read_index

import os
from subprocess import PIPE, Popen
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


def main():
    module = AnsibleModule(
        argument_spec=dict(
            issued=dict(type='list', elements='str'),
            ca_dir=dict(type='str'),
            server=dict(type='str')
        )
    )
    params = module.params
    clients = params['issued']

    ca_dir = params['ca_dir']

    def ca_path(*args):
        return os.path.join(ca_dir, *args)

    issued, revoked = read_index(ca_dir)

    os.makedirs(ca_path('pki/tmp'), exist_ok=True)

    res = {
        'changed': False,
        'issued': [],
        'files': [],
        'errors': []
    }

    for client in clients:
        if client not in issued:

            proc = Popen(['easyrsa', '--batch', 'build-client-full', client, 'nopass'], stderr=PIPE, stdout=PIPE, cwd=ca_dir)

            stdout, stderr = proc.communicate()

            if proc.returncode != 0:
                res['errors'].append({
                    'client': client,
                    'stdout': stdout,
                    'stderr': stderr
                })
                continue

            args = Args(
                server=params['server'],
                ca=ca_path('pki/ca.crt'),
                ta=ca_path('pki/private/ta.key'),
                cert=ca_path(f'pki/issued/{client}.crt'),
                key=ca_path(f'pki/private/{client}.key'),
            )

            ovpn_path = ca_path(f'pki/tmp/{client}.ovpn')
            zip_path = ca_path(f'pki/tmp/{client}.zip')

            create_ovpn(args, ovpn_path)
            create_zip(args, zip_path)

            res['changed'] = True
            res['files'].append(ovpn_path)
            res['files'].append(zip_path)
            res['issued'].append(client)

    module.exit_json(**res)

if __name__ == "__main__":
    main()