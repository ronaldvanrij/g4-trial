import argparse
import os

from lib import cert
from lib.util import load_yaml, choose


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('csrfiles', nargs='+', help="YAML Certificate Signing Requests to be signed")
    args = parser.parse_args()

    options = load_yaml("options.yaml")['domains']

    domain = choose("Choose domain:", list(options.keys()))
    cert_type = choose("Choose certificate type:", options[domain]['endentity'])

    profilefile = os.path.join('profiles', cert_type['profile'])

    print(f'To automate this step, run next time:')
    print(f'python generate-cert.py "{profilefile}" {' '.join([f'"{csrfile}"' for csrfile in args.csrfiles])}')

    for csrfile in args.csrfiles:
        cert.process(profilefile, csrfile)


if __name__ == "__main__":
    main()
