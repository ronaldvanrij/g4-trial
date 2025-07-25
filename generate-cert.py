import argparse

from lib.util import load_yaml
from lib import cert

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('profile', help="YAML Certificate profile filename")
    parser.add_argument('csrfiles', nargs='+', help="YAML Certificate Signing Requests to be signed")
    args = parser.parse_args()

    config = load_yaml("config.yaml")

    for csrfile in args.csrfiles:
        cert.process(args.profile, csrfile, config)
