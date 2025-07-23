import hashlib
from collections import OrderedDict
import re
import yaml
from cryptography.x509 import Name
from cryptography.x509.oid import NameOID


class OID:
    def __init__(self, short_name, long_name, oid):
        self.short_name = short_name
        self.long_name = long_name
        self.oid = oid


attributes = [
    OID('C', 'country', NameOID.COUNTRY_NAME),
    OID('ST', 'stateOrProvinceName', NameOID.STATE_OR_PROVINCE_NAME),
    OID('L', 'localityName', NameOID.LOCALITY_NAME),
    OID('', 'postalCode', NameOID.POSTAL_CODE),
    OID('', 'streetAddress', NameOID.STREET_ADDRESS),
    OID('O', 'organizationName', NameOID.ORGANIZATION_NAME),
    OID("SN", 'surName', NameOID.SURNAME),
    OID("GN", 'givenName', NameOID.GIVEN_NAME),
    OID("", 'organizationalUnitName', NameOID.ORGANIZATIONAL_UNIT_NAME),
    OID('CN', 'commonName', NameOID.COMMON_NAME),
    OID('', 'organizationIdentifier', NameOID.ORGANIZATION_IDENTIFIER),
    OID('', 'serialNumber', NameOID.SERIAL_NUMBER),
    OID('', 'title', NameOID.TITLE),
]


class DN(OrderedDict):

    @staticmethod
    def parse_dict(d):
        if not isinstance(d, dict):
            raise Exception(f"Unhandled type: {type(d)}")

        # Assume *unordered*: sort, while replacing shortnames with long names
        dn = DN()
        for attribute in attributes:
            if attribute.short_name in d and not d[attribute.short_name].startswith('omit'):
                dn[attribute.short_name] = d[attribute.short_name]
            elif attribute.long_name in d and not d[attribute.long_name].startswith('omit'):
                dn[attribute.long_name] = d[attribute.long_name]
            elif attribute.oid.dotted_string in d and not d[attribute.oid.dotted_string].startswith('omit'):
                dn[attribute.attribute.oid.dotted_string] = d[attribute.oid.dotted_string]
        return dn

    @staticmethod
    def parse_list(d):
        """
        Create a DN object from the YAML formatting: an ordered array of single element dicts
        :param d:
        :return:
        """
        if not isinstance(d, list):
            raise Exception(f"Unhandled type: {type(d)}")

        dn = DN()
        # Assume an *ordered* list of single element dicts (which could be ordered, but let's not assume)
        for item in d:
            for k, v in item.items():
                dn[k] = v
        return dn

    def generate_basename(self, fallback=None):
        """
        Compute the default name used for its issuer by EJBCA
        """
        if 'CN' in self and not self['CN'].startswith("omit"):
            return re.compile('[^a-zA-Z0-9_]+').sub('', self['CN'])

        if fallback is not None:
            return fallback

        # Unique hash
        subject_str = str(self.items())
        return "cert_" + hashlib.sha1(subject_str.encode()).hexdigest()[:8]

    def as_rfc4514_string(self):
        """
        Returns this DN as an RFC 4514 string.
        Please note:
         1. Components are comma separated
         2. The order is reversed to the slash '/' separated strings
        :return:
        """
        merged = []
        for k, v in self.items():
            merged.append(f'{k}={v}')
        return ','.join(reversed(merged))

    def as_rfc4514_dotted_string(self):
        """
        Returns this DN as an ordered RFC 4514 string.
        Please note:
         1. Components are comma separated
         2. The order is reversed to the slash '/' separated strings
        :return:
        """
        merged = []
        for k, v in self.items():
            for attribute in attributes:
                if k in [attribute.short_name, attribute.long_name, attribute.oid.dotted_string]:
                    merged.append(f'{attribute.oid.dotted_string}={v}')
        return ','.join(reversed(merged))

    def to_yaml(self):
        return [{k: v} for k, v in self.items()]

    def as_name(self):
        """
        Returns this object as a x509.Name object
        :return:
        """
        # Note: use the dotted string OID, so that a override dict (from user friendly name to OID) is not necessary
        return Name.from_rfc4514_string(self.as_rfc4514_dotted_string())


# YAML voodoo

def represent_myclass_as_list(dumper, obj):
    return dumper.represent_sequence('!DN', obj.to_yaml())


yaml.add_representer(DN, represent_myclass_as_list)


# Constructor that preserves order
def dn_constructor(loader, node):
    items = loader.construct_sequence(node, True)
    ordered = DN()
    for item in items:
        ordered.update(item)
    return ordered


yaml.add_constructor('!DN', dn_constructor, Loader=yaml.SafeLoader)


def postprocess_yaml(raw):
    if 'subject' in raw:
        if isinstance(raw['subject'], dict):
            raw['subject'] = DN.parse_dict(raw['subject'])
        elif isinstance(raw['subject'], list):
            raw['subject'] = DN.parse_list(raw['subject'])
        elif isinstance(raw['subject'], DN):
            pass  # Already correct type
        else:
            raise Exception(f"Unparseable type {raw['subject']}")
    if 'issuer' in raw:
        if isinstance(raw['issuer'], dict):
            raw['issuer'] = DN.parse_dict(raw['issuer'])
        elif isinstance(raw['issuer'], list):
            raw['issuer'] = DN.parse_list(raw['issuer'])
        elif isinstance(raw['issuer'], DN):
            pass  # Already correct type
        else:
            raise Exception(f"Unparseable type {raw['subject']}")
    if 'issues' in raw:
        for item in raw['issues']:
            postprocess_yaml(item)
