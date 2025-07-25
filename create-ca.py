from lib import cert
from lib import crl
from lib.util import load_yaml, choose, load_config
from lib.domains import verify


def main():

    config = load_config()

    options = load_yaml("domains.yaml")['domains']
    if not verify(options):
        exit(1)

    hierarchy = choose("Choose a domain:", list(options.keys()))

    # Creating a hierarchy means creating a number of keys
    for layer in options[hierarchy]['hierarchy']:
        cert.process(layer['profile'], layer['csr'], config)
        crl.process(layer['revocations'], force=True)

    print(f'To automate this step, run next time:')
    for layer in options[hierarchy]['hierarchy']:
        print(f'python generate-cert.py "{layer['profile']}" "{layer['csr']}"')
        print(f'python generate-crl.py --force "{layer['revocations']}"')


if __name__ == "__main__":
    main()
