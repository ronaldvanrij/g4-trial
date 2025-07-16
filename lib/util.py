import yaml
import sys

from cryptography.hazmat.primitives import hashes


def force_int(value):
    if isinstance(value, int):
        return value
    elif isinstance(value, str):
        first = value.split(" ")[0]
        if first.startswith('0x'):
            return int(first, 16)
        return int(first)
    return value


def get_hash_algo(name):
    name = name.lower()
    return {
        'sha512': hashes.SHA512(),
        'sha384': hashes.SHA384(),
        'sha256': hashes.SHA256(),
    }[name]


def load_yaml(filename):
    with open(filename, 'r') as f:
        return yaml.safe_load(f)


def load_yaml_merged(filename):
    """
    Some YAML files may contain several documents. Collapse them
    :param filename:
    :return:
    """
    with open(filename, 'r') as f:
        docs = yaml.safe_load_all(f)
        merged = {}
        [merged.update(doc) for doc in docs if doc]
        return merged


def keys_exist(d, path):
    """
    Recursively checks if a sequence of nested keys exists in a dictionary.

    :param d: The dictionary to check.
    :param path: A list of keys representing the nested path.
    :return: True if all keys exist in sequence, False otherwise.
    """
    if not path:  # Base case: if no keys are left to check, return True
        return True
    if not isinstance(d, dict) or path[0] not in d:
        return False
    # Recursive call for the next level, passing the rest of the keys
    return keys_exist(d[path[0]], path[1:])


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def output_errors(errors):
    for error in errors:
        # print(error)
        if 'error' in error:
            print(f"- {error['instanceLocation']}: {error['error']}")
        else:
            output_errors(error['errors'])