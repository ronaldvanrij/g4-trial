#!/bin/bash

set -e

usage() { echo "Usage: $0 [-f input file]" 1>&2; exit 1; }

inputfile=endentitycerts.txt

while getopts "h?f:" opt; do
  case "$opt" in
    h|\?)
      usage
      exit 0
      ;;
    f)  inputfile=$OPTARG
      ;;
  esac
done

if ! test -f "$inputfile"; then
  echo "End entity input file $inputfile not found" && usage && exit 1
fi

echo Using "$inputfile"

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "Specify the domain for which you want to create End Entity certificates:"
. "$SCRIPT_DIR"/.prompt

. "$SCRIPT_DIR"/.includes

# Validate CA status and inputs
if ! test -f "$CERT_DIR/$issuingbasename.pem"; then
  echo "Issuing certificate $CERT_DIR/$issuingbasename.pem does not exists. Create it first using create_ca.sh" && exit 1
fi

if ! test -f "$PRIVATE_DIR/$issuingbasename.key"; then
  echo "Issuing private key $PRIVATE_DIR/$issuingbasename.key does not exist. Create it first using create_ca.sh" && exit 1
fi

# Validate input document
while IFS=, read basename dn san
do

  file="$PRIVATE_DIR/$basename.key"
  if test -f "$file"; then
    echo "Private key file $file exists. Choose a different basename" && exit 1
  fi

  file="$CSR_DIR/$basename.csr"
  if test -f "$file"; then
    echo "Certificate Signing Request file $file exists. Choose a different basename" && exit 1
  fi

  file="$CERT_DIR/$basename.pem"
  if test -f "$file"; then
     echo "Certificate file $file exists. Choose a different basename" && exit 1
  fi
done < <(grep -Ev '^#' "$inputfile" | grep -v "^$")

# Parse the input file and create the end entity certificates
echo "Creating certificates from file $inputfile"

unset outfiles

while IFS=, read basename dn san
do

  # Generate and issue end entity key
  # -----------------------------------------

  # Needs qcStatement?
  organizationIdentifier=$(echo "$dn" | sed -n 's#.*/organizationIdentifier=\(NTRNL[^/]*\).*#\1#p')
  if [[ -n $organizationIdentifier ]]; then
    echo found
    extensions="v3_end_entity_legal"
  else
    extensions="v3_end_entity"
  fi

  export SAN=$san
  openssl genpkey ${genpkeyopt} -out "$PRIVATE_DIR/$basename.key"
  openssl req ${reqopt} -key "$PRIVATE_DIR/$basename.key" -out "$CSR_DIR/$basename.csr" -subj "${dn}"
  openssl ca ${caopt} -days ${eedays} -extensions ${extensions} ${extopt} -policy policy_end_entity -in "$CSR_DIR/$basename.csr" -out "$CERT_DIR/$basename.pem" -cert "$CERT_DIR/$issuingbasename.pem" -keyfile "$PRIVATE_DIR/$issuingbasename.key"
  openssl x509 -in "$CERT_DIR/$basename.pem" -noout -text > "$CERT_DIR/${basename}_text.txt"

  outfiles+=("$basename")
done < <(grep -Ev '^#' "$inputfile" | grep -v "^$")

echo
echo "Successfully created private keys and issued test certificates:"
for basename in "${outfiles[@]}"
do
   echo "  keyfile: $PRIVATE_DIR/$basename.key"
   echo "  certificate file: $CERT_DIR/$basename.pem"
done


