import argparse

from lib import crl


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--force', action='store_true', help="If files are absent, generate boilerplate YAML and CRL files")
    parser.add_argument('revocations', nargs='+', help="Generate CRLs for these files")
    args = parser.parse_args()

    for revocation in args.revocations:
        crl.process(revocation, args.force)


if __name__ == "__main__":
    main()
