import os

def read_index(ca_path):
    path = os.path.join(ca_path, 'pki', 'index.txt')
    issued = []
    revoked = []
    with open(path) as f:
        for line in f:
            line = line.rstrip('\n')
            cols = line.split('\t')
            op = cols[0]
            name = cols[-1]
            if name.startswith('/CN='):
                name = name[4:]
            if op == 'V':
                issued.append(name)
            elif op == 'R':
                revoked.append(name)
    return issued, revoked