import unittest
from collections import OrderedDict

import yaml

from dn import DN


class TestDN(unittest.TestCase):

    def test_from_yaml_creates_correct_ordered_dict(self):
        yaml_str = """
        C: US
        O: ExampleOrg
        CN: example.com
        """
        parsed_yaml = yaml.safe_load(yaml_str)

        # Ensure parsed_yaml is still ordered (PyYAML 5.1+ preserves order by default)
        dn = DN.parse_dict(parsed_yaml)

        expected = OrderedDict([
            ('C', 'US'),
            ('O', 'ExampleOrg'),
            ('CN', 'example.com')
        ])
        self.assertIsInstance(dn, DN)
        self.assertEqual(list(dn.items()), list(expected.items()))

    def test_generate_basename_omit_cn(self):
        dn = DN()
        dn['CN'] = 'omitThisName'
        basename = dn.generate_basename('fallbackCN')
        self.assertEqual(basename, 'fallbackCN')

    def test_generate_basename_no_cn(self):
        dn = DN()
        basename = dn.generate_basename('fallbackCN')
        self.assertEqual(basename, 'fallbackCN')

    def test_generate_basename(self):
        dn = DN()
        dn['CN'] = 'example@domain.com'
        basename = dn.generate_basename('fallback')
        self.assertEqual(basename, 'exampledomaincom')

    def test_as_rfc4514_string(self):
        dn = DN()
        dn['C'] = 'NL'
        dn['O'] = 'Company'
        dn['CN'] = 'localhost.com'
        result = dn.as_rfc4514_string()
        expected = 'CN=localhost.com,O=Company,C=NL'
        self.assertEqual(result, expected)

    def test_to_yaml(self):
        ordered_input = DN([
            ('C', 'US'),
            ('ST', 'California'),
            ('L', 'Mountain View'),
            ('O', 'OpenAI'),
            ('CN', 'chat.openai.com')
        ])

        actual = ordered_input.to_yaml()
        expected = [{'C': 'US'}, {'ST': 'California'}, {'L': 'Mountain View'}, {'O': 'OpenAI'}, {'CN': 'chat.openai.com'}]
        self.assertEqual(actual, expected)

        expected = """!DN
- C: US
- ST: California
- L: Mountain View
- O: OpenAI
- CN: chat.openai.com
"""

        actual = yaml.dump(ordered_input)
        self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
