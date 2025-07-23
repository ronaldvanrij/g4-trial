import argparse

from lib import cert
from lib.util import load_yaml, choose, load_config
from lib.domains import verify


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('csrfiles', nargs='+', help="YAML Certificate Signing Requests to be signed")
    args = parser.parse_args()

    config = load_config()

    options = load_yaml("domains.yaml")['domains']
    if not verify(options):
        exit(1)

    domain = choose("Choose domain:", list(options.keys()))
    cert_type = choose("Choose certificate type:", options[domain]['endentity'])

    profilefile = cert_type['profile']

    print(f'To automate this step, run next time:')
    print(f'python generate-cert.py "{profilefile}" {' '.join([f'"{csrfile}"' for csrfile in args.csrfiles])}')

    for csrfile in args.csrfiles:
        cert.process(profilefile, csrfile, config)


if __name__ == "__main__":
    main()
