import os
import argparse
import pathlib
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.x509.extensions import BasicConstraints
from jschon import create_catalog, JSON, JSONSchema
from lib.keypair import KeyPair
from lib.crl import generate_crl
from lib.util import load_yaml, eprint, output_errors

parser = argparse.ArgumentParser()
parser.add_argument('-f', '--force', action='store_true', help="If files are absent, generate boilerplate YAML and CRL files")
parser.add_argument('revocations', nargs='*', help="Generate CRLs for these files")
args = parser.parse_args()

catalog = create_catalog("2020-12")
schema = JSONSchema.loadf(os.path.join('schema', 'revocations.json'))

for revocation in args.revocations:

    # Find keys
    ca_keys = KeyPair(pathlib.Path(revocation).stem).load()

    # Check must be a CA
    basicConstraints = ca_keys.certificate.extensions.get_extension_for_class(BasicConstraints).value
    if not basicConstraints.ca:
        eprint(f'Cannot create a CRL for non-CA certificates. Skipping')
        exit(0)

    # If absent create a boilerplate file
    if args.force and not os.path.exists(revocation):
        # Write a boilerplate YAML
        d = {'revocations': []}
        with open(revocation, 'w') as outfile:
            outfile.write("---\n")
            yaml.dump(d, outfile, default_flow_style=False)

    # Validate input
    profile = load_yaml(revocation)

    instance = JSON(profile)
    result = schema.evaluate(instance)
    if not result.valid:
        print(f"{revocation} is invalid to generate a CRL ❌")
        output_errors(result.output("detailed")["errors"])
        exit(1)

    # Generate CRL
    crl = generate_crl(profile['revocations'], ca_keys)

    # Write to disk
    newpath = os.path.join('ca', 'crl')
    if not os.path.exists(newpath):
        os.makedirs(newpath)

    filename = os.path.join('ca', 'crl', f"{ca_keys.basename}.crl")
    with open(filename, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.DER))

    print(f"CRL signed {len(profile['revocations'])} revocations and saved to {filename}")