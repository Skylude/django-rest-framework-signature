import random
import datetime
import django
import os

os.environ['DJANGO_SETTINGS_MODULE'] = 'test_projects.test_proj.settings'
django.setup()

from rest_framework_signature.helpers import *
from time import sleep


class RestFrameworkSignatureHelpersTests(RestFrameworkSignatureTestClass):
    def test_sort_body_containing_list(self):
        # Arrange
        body = dict(communities=[1, 2421])

        # Act
        result = sort_body(body)

        # Assert
        self.assertEqual(result, body)

    def test_sort_body_with_multiple_kv(self):
        # Arrange
        body_1 = {'residentId': random.randint(1, 100),
                  'cancelReasonId': random.randint(1, 100),
                  'signupMethodId': random.randint(1, 100)}
        body_2 = {'residentId': random.randint(1, 100)}
        body_3 = {'residentId': random.randint(1, 100), 'empty_array': []}

        # Act
        result_1 = sort_body(body_1)
        result_2 = sort_body(body_2)
        result_3 = sort_body(body_3)

        # Assert
        self.assertEqual(result_1, body_1)
        self.assertEqual(result_2, body_2)
        self.assertEqual(result_3, body_3)

    def test_sort_body_with_nested_objects(self):
        # Arrange
        body = {
            'array_1': [900, 'a', 'b', 3, 'd'],
            'array_2': [{'id': 1}, {'id': 2}, {'id': 3}],
            'array_c': [{'{foo': '{"bar": "oque"}'}],
            'dict_1': dict(pen='Pineapple', pineapple='pen',
                           put_them_together=['pen', 'pineapple', 'pineapple',
                                              {'apple': 'pineappleapplepen'}]),
            'simple_object': 'rocketMortgageByQuickenLoansTM',
            'Null object': None,
            'string_object': 'string'
        }

        # Act
        result = sort_body(body)

        # Assert
        self.assertEqual(result, body)

    def test_sort_body_with_simple_body(self):
        body_1 = 1
        body_2 = None
        body_3 = ''

        # Act
        result_1 = sort_body(body_1)
        result_2 = sort_body(body_2)
        result_3 = sort_body(body_3)

        # Assert
        self.assertEqual(result_1, body_1)
        self.assertEqual(result_2, body_2)
        self.assertEqual(result_3, body_3)

    def test_sort_body_with_simple_array_body(self):
        # Arrange
        body_1 = [1]
        body_2 = '[1]'
        body_3 = [[1]]

        # Act
        result_1 = sort_body(body_1)
        result_2 = sort_body(body_2)
        result_3 = sort_body(body_3)

        # Assert
        self.assertEqual(result_1, body_1)
        self.assertEqual(result_2, body_2)
        self.assertEqual(result_3, body_3)

    def test_sort_body_with_simple_json_body(self):
        # Arrange
        body_1 = {0: 1}
        body_2 = '{0: 1}'
        body_3 = {'[[1]]': 0}

        # Act
        result_1 = sort_body(body_1)
        result_2 = sort_body(body_2)
        result_3 = sort_body(body_3)

        # Assert
        self.assertEqual(result_1, body_1)
        self.assertEqual(result_2, body_2)
        self.assertEqual(result_3, body_3)

    def test_sort_body_edge_cases_1(self):
        # Arrange
        body_1 = {None: None}
        body_2 = {'var': '{None: [None]}'}
        body_3 = {1: str({'None': 0})}
        body_4 = {'var': {None: [None]}}

        # Act
        result_1 = sort_body(body_1)
        result_2 = sort_body(body_2)
        result_3 = sort_body(body_3)
        result_4 = sort_body(body_4)

        # Assert
        self.assertEqual(result_1, body_1)
        self.assertEqual(result_2, body_2)
        self.assertEqual(result_3, body_3)
        self.assertEqual(result_4, body_4)

    def test_sort_body_edge_cases_2(self):
        # Arrange
        body_1 = {'never': '{None: None}'}
        body_2 = {'gonna': {'var': '{None: [None]}'}}
        body_3 = {'give': {1: str({'None': 0})}}
        body_4 = {'you': {'var': {None: [None]}}}
        body_5 = {'up': 'lorem ipsum', str(body_1): str(body_2), str(body_3): str(body_4), '': []}

        # Act
        result_1 = sort_body(body_1)
        result_2 = sort_body(body_2)
        result_3 = sort_body(body_3)
        result_4 = sort_body(body_4)
        result_5 = sort_body(body_5)

        # Assert
        self.assertEqual(result_1, body_1)
        self.assertEqual(result_2, body_2)
        self.assertEqual(result_3, body_3)
        self.assertEqual(result_4, body_4)
        self.assertEqual(result_5, body_5)

    def test_sort_body_edge_cases_3(self):
        # Arrange
        body_1 = {'never': set(str([{None: None}]))}
        body_2 = {'gonna': {'var': '{None: [None]}'}}
        body_3 = {'give': {1: str({'None': 0})}}
        body_4 = {'you': """{
            'array_1': [900, 'a', 'b', 3, 'd'],
            'array_2': [{'id': 1}, {'id': 2}, {'id': 3}],
            'array_c': [{'{foo': '{"bar": "oque"}'}],
            'dict_1': dict(pen='Pineapple', pineapple='pen',
                           put_them_together=['pen', 'pineapple', 'pineapple',
                                              {'apple': 'pineappleapplepen'}]),
            'simple_object': 'rocketMortgageByQuickenLoansTM',
            'Null object': None,
            'string_object': 'string'
        }"""}
        body_5 = {'up': 'lorem ipsum', str(body_1): str(body_2), str(body_3): str(body_4), '': []}

        # Act
        result_1 = sort_body(body_1)
        result_2 = sort_body(body_2)
        result_3 = sort_body(body_3)
        result_4 = sort_body(body_4)
        result_5 = sort_body(body_5)

        # Assert
        self.assertEqual(result_1, body_1)
        self.assertEqual(result_2, body_2)
        self.assertEqual(result_3, body_3)
        self.assertEqual(result_4, body_4)
        self.assertEqual(result_5, body_5)

    def test_nonce_equality(self):
        timestamp = datetime.datetime.timestamp(datetime.datetime.now())
        url = 'asdfjhkl(handy);-thatsnotallasyoucantell'
        secret = 'ssssssssssssssshhhhhhhhhhhhhhhhhhhhhhhhhhh...............'
        body = """{
            'array_1': [900, 'a', 'b', 3, 'd'],
            'array_2': [{'id': 1}, {'id': 2}, {'id': 3}],
            'array_c': [{'{foo': '{"bar": "oque"}'}],
            'dict_1': dict(pen='Pineapple', pineapple='pen',
                           put_them_together=['pen', 'pineapple', 'pineapple',
                                              {'apple': 'pineappleapplepen'}]),
            'simple_object': 'rocketMortgageByQuickenLoansTM',
            'Null object': None,
            'string_object': 'string'
        }"""

        result_1 = get_nonce(timestamp, url, secret, body=body)

        sleep(5)

        result_2 = get_nonce(timestamp, url, secret, body=body)

        self.assertEqual(result_1, result_2)
