import unittest
from warrant.utilities import merge_dicts
import json


class UtilitiesTestCase(unittest.TestCase):
    def test_merge_dicts(self):
        dict1 = {'squirrel': 1, 'bird': 2}
        dict2 = {'lion': 3, 'flower': 4}
        expected = {'squirrel': 1, 'bird': 2, 'lion': 3, 'flower': 4}
        print(json.dumps(merge_dicts(dict1=dict1, dict2=dict2)))
        self.assertEqual(expected, merge_dicts(dict1=dict1, dict2=dict2))

    def test_merge_dicts_duplicate_key(self):
        # dict2 overwrites the value from dict1
        dict1 = {'squirrel': 1, 'bird': 2}
        dict2 = {'squirrel': 2, 'flower': 3}
        expected = {'squirrel': 2, 'bird': 2, 'flower': 3}
        print(json.dumps(merge_dicts(dict1=dict1, dict2=dict2)))
        self.assertEqual(expected, merge_dicts(dict1=dict1, dict2=dict2))

    def test_merge_dicts_invalid_type_not_a_dict1(self):
        dict1 = ['incorrect', 'invalid']
        dict2 = {'squirrel': 1, 'bird': 2}
        self.assertRaises(TypeError, merge_dicts, dict1, dict2)

    def test_merge_dicts_invalid_type_not_a_dict2(self):
        dict1 = {'squirrel': 1, 'bird': 2}
        dict2 = ['incorrect', 'invalid']
        self.assertRaises(TypeError, merge_dicts, dict1, dict2)
