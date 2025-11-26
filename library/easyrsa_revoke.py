from ansible.module_utils.basic import AnsibleModule

from ansible.module_utils.openvpn import read_index

from subprocess import PIPE, Popen

def main(): 
    module = AnsibleModule(
        argument_spec=dict(
            revoked=dict(type='list', elements='str'),
            ca_dir=dict(type='str')
        )
    )
    params = module.params
    ca_dir = params['ca_dir']
    clients = params['revoked']

    issued, revoked = read_index(ca_dir)

    res = {
        'changed': False,
        'revoked': [],
        'errors': [],
        #'debug': [{'issued': issued, 'revoked': revoked}]
    }

    for client in clients:
        if client not in revoked:
            proc = Popen(['easyrsa', '--batch', 'revoke', client], cwd=ca_dir)
            stdout, stderr = proc.communicate()
            if proc.returncode != 0:
                res['errors'].append({
                    'client': client,
                    'stdout': stdout,
                    'stderr': stderr
                })
                continue
            res['revoked'].append(client)
            res['changed'] = True
    module.exit_json(**res)

if __name__ == "__main__":
    main()