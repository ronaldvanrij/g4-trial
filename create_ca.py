from lib import cert
from lib import crl
from lib.util import load_yaml, choose


def main():

    options = load_yaml("options.yaml")['domains']

    hierarchy = choose("Choose a domain:", list(options.keys()))

    # Creating a hierarchy means creating a number of keys
    for layer in options[hierarchy]['hierarchy']:
        cert.process(layer['profile'], layer['csr'])
        crl.process(layer['revocations'], force=True)

    print(f'To automate this step, run next time:')
    for layer in options[hierarchy]['hierarchy']:
        print(f'python generate-cert.py "{layer['profile']}" "{layer['csr']}"')
        print(f'python generate-crl.py --force "{layer['revocations']}"')


if __name__ == "__main__":
    main()
