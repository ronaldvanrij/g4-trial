import argparse
import os

from lib.cert import process
from lib.util import load_yaml, choose


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('csrs', nargs='+', help="YAML Certificate Signing Requests to be signed")
    args = parser.parse_args()

    options = load_yaml("options.yaml")['endentity']

    hierarchy = choose("Choose hierarchy:", list(options.keys()))
    cert_type = choose("Choose certificate type:", options[hierarchy])

    profilefile = os.path.join('profiles', cert_type['profile'])

    print(f'To automate this step, run next time:')
    print(f'python generate-cert.py "{profilefile}" {' '.join([f'"{csr}"' for csr in args.csrs])}')

    process(profilefile, args.csrs)

if __name__ == "__main__":
    main()
