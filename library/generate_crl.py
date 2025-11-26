from ansible.module_utils.basic import AnsibleModule

from ansible.module_utils.openvpnutils import is_legacy_ca

from subprocess import Popen, PIPE, check_output
import shutil
import os

def generate_crl(ca_dir):
    proc = Popen(['easyrsa', '--batch', 'gen-crl'], stderr=PIPE, stdout=PIPE, cwd=ca_dir)
    return proc, os.path.join(ca_dir,'pki/crl.pem')

def generate_crl_legacy(ca_dir):
    #$OPENSSL ca -gencrl -out "$CRL" -config "$KEY_CONFIG"
    KEY_CONFIG = check_output(['./whichopensslcnf', ca_dir], cwd=ca_dir).decode('utf-8').split('\n')[0]
    proc = Popen(['openssl', 'ca', '-gencrl', '-out', 'keys/crl.pem', '-config', KEY_CONFIG], cwd=ca_dir)
    return proc, os.path.join(ca_dir, 'keys/crl.pem')

def main():
    module = AnsibleModule(
        argument_spec=dict(
            ca_dir=dict(type='str'),
        )
    )
    params = module.params
    ca_dir = params['ca_dir']
    
    res = {
        'changed': False,
        'issued': [],
        'files': [],
        'errors': [],
        'debug': []
    }

    legacy_ca = is_legacy_ca(ca_dir, res)

    if legacy_ca:
        proc, crl_src = generate_crl_legacy(ca_dir)
    else:
        proc, crl_src = generate_crl(ca_dir)
    
    try:
        stdout, stderr = proc.communicate()
    except Exception as e:
        stdout = ''
        stderr = ''
        res['errors'].append(str(e))

    crl_dst = '/etc/openvpn/crl.pem'
    if os.path.exists(crl_src):
        try:
            shutil.copy2(crl_src, crl_dst)
        except Exception as e:
            res['errors'].append(str(e))
    else:
        res['debug'].append(f'file not exist {crl_src}')

    res['changed'] = True
    if proc.returncode != 0:
        res['errors'].append({'stdout': stdout, 'stderr': stderr})

    res['errors'].append({'stdout': stdout, 'stderr': stderr})

    module.exit_json(**res)

if __name__ == "__main__":
    main()