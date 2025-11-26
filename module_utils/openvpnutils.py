import os
import re
import subprocess

def read_index(ca_dir):
    path1 = os.path.join(ca_dir, 'pki', 'index.txt')
    path2 = os.path.join(ca_dir, 'keys', 'index.txt')
    issued = []
    revoked = []
    for path in [path1, path2]:
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    line = line.rstrip('\n')
                    cols = line.split('\t')
                    op = cols[0]
                    name = None
                    for item in cols[-1].split('/'):
                        if '=' in item:
                            n, val = item.split('=', 1)
                            if n == 'CN':
                                name = val
                    if op == 'V':
                        issued.append(name)
                    elif op == 'R':
                        revoked.append(name)
            break
    return issued, revoked

def is_legacy_ca(ca_dir, res):
    def ca_path(*args):
        return os.path.join(ca_dir, *args)
    pki_dir = os.path.exists(ca_path('pki'))
    keys_dir = os.path.exists(ca_path('keys'))
    legacy_ca = False
    if pki_dir == keys_dir:
        if res is not None:
            res['debug'].append(f'pki_dir == keys_dir == {pki_dir}')
    elif pki_dir:
        legacy_ca = False
    elif keys_dir:
        legacy_ca = True
    if res is not None:
        res['debug'].append(f'legacy_ca == {legacy_ca}')
    return legacy_ca

def unquote(s):
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s

def read_env(path):
    res = dict()
    with open(path) as f:
        line: str
        for line in f:
            line = line.strip()
            if line.startswith('#'):
                continue
            m = re.match("export ([^=]+)=(.*)", line, flags=re.IGNORECASE)
            if m:
                n = m.group(1).strip()
                v = unquote(m.group(2).strip())
                res[n] = v
                continue
            m = re.match("([^=]+)=(.*)", line, flags=re.IGNORECASE)
            if m:
                n = m.group(1).strip()
                v = unquote(m.group(2).strip())
                res[n] = v
                continue
    return res

def source_vars(ca_dir):
    def ca_path(*args):
        return os.path.join(ca_dir, *args)
    vars_path = ca_path('vars')
    if not os.path.exists(vars_path):
        raise ValueError(f'vars file {vars_path} not found')
    env = dict(os.environ)
    env1 = read_env(vars_path)
    if len(env1) == 0:
        raise ValueError('no vars in vars file, its not legacy easyrsa dir?')
    env.update(env1)
    env['KEY_DIR'] = ca_path('keys')
    env['EASY_RSA'] = ca_dir
    env['KEY_CONFIG'] = subprocess.check_output(['./whichopensslcnf', ca_dir], cwd=ca_dir).decode('utf-8').split('\n')[0]
    return env