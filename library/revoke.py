from ansible.module_utils.basic import AnsibleModule

from ansible.module_utils.openvpnutils import read_index, is_legacy_ca, source_vars

from subprocess import PIPE, Popen

def revoke(client, params, res):
    ca_dir = params['ca_dir']
    proc = Popen(['easyrsa', '--batch', 'revoke', client], cwd=ca_dir)
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        res['errors'].append({
            'client': client,
            'stdout': stdout,
            'stderr': stderr
        })
        return
    res['changed'] = True
    res['revoked'].append(client)

def revoke_legacy(client, params, res):
    ca_dir = params['ca_dir']
    env = source_vars(ca_dir)
    proc = Popen(['./revoke-full', client], env = env, cwd = ca_dir)
    stdout, stderr = proc.communicate()
    # it always fails
    res['debug'].append({'client': client, 'stdout': stdout, 'stderr': stderr, 'returncode': proc.returncode})
    res['changed'] = True
    res['revoked'].append(client)

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
        'debug': [],
        'errors': []
    }

    legacy_ca = is_legacy_ca(ca_dir, res)

    if legacy_ca:
        revoke_fn = revoke_legacy
    else:
        revoke_fn = revoke

    for client in clients:
        if client not in revoked:
            revoke_fn(client, params, res)
            
    module.exit_json(**res)

if __name__ == "__main__":
    main()