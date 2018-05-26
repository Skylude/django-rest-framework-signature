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
        body_unsorted = {
            'Image': {
                'Width': 800,
                'Height': 600,
                'Title': 'View from 15th Floor',
                'Thumbnail': {
                    'Url': 'http://www.example.com/image/481989943',
                    'Height': 125,
                    'Width': 100
                },
                'Animated': False,
                'IDs': [116, 943, 234, 38793]
            }
        }
        body_sorted = {
            'Image':
                {
                    'Animated': False,
                    'Height': 600,
                    'IDs': [116, 943, 234, 38793],
                    'Thumbnail': {
                        'Height': 125,
                        'Url': 'http://www.example.com/image/481989943',
                        'Width': 100
                    },
                    'Title': 'View from 15th Floor',
                    'Width': 800
                }
        }

        # Act
        result = sort_body(body_unsorted)

        # Assert
        self.assertEqual(result, body_sorted)

    def test_sort_body_with_nested_objects(self):
        # Arrange
        body = {
            'location': [
                {
                    'precision': 'zip',
                    'Latitude': 37.7668,
                    'Longitude': -122.3959,
                    'Address': '',
                    'City': 'SAN FRANCISCO',
                    'State': 'CA',
                    'Zip': '94107',
                    'Country': 'US'
                },
                {
                    'precision': 'zip',
                    'Latitude': 37.371991,
                    'Longitude': -122.026020,
                    'Address': '',
                    'City': 'SUNNYVALE',
                    'State': 'CA',
                    'Zip': '94085',
                    'Country': 'US'
                }
            ],
            'dataset_name': 'Sunnyville Geography'
        }
        sorted_body = OrderedDict({
            'dataset_name': 'Sunnyville Geography',
            'location': [
                {
                    'Address': '',
                    'City': 'SAN FRANCISCO',
                    'Country': 'US',
                    'Latitude': 37.7668,
                    'Longitude': -122.3959,
                    'precision': 'zip',
                    'State': 'CA',
                    'Zip': '94107'
                },
                {
                    'Address': '',
                    'City': 'SUNNYVALE',
                    'Country': 'US',
                    'Latitude': 37.371991,
                    'Longitude': -122.026020,
                    'precision': 'zip',
                    'State': 'CA',
                    'Zip': '94085'
                }
            ]
        })
        expected_body = OrderedDict([('dataset_name', 'Sunnyville Geography'),
                                     ('location', [
                                         OrderedDict([
                                             ('Address', ''),
                                             ('City', 'SAN FRANCISCO'),
                                             ('Country', 'US'),
                                             ('Latitude', 37.7668),
                                             ('Longitude', -122.3959),
                                             ('State', 'CA'),
                                             ('Zip', 94107),
                                             ('precision', 'zip')
                                         ]),
                                         OrderedDict([
                                             ('Address', ''),
                                             ('City', 'SUNNYVALE'),
                                             ('Country', 'US'),
                                             ('Latitude', 37.371991),
                                             ('Longitude', -122.02602),
                                             ('State', 'CA'),
                                             ('Zip', 94085),
                                             ('precision', 'zip')
                                         ])
                                     ])])
        # Act
        result = sort_body(body)

        # Assert
        self.assertEqual(result, expected_body)

    def test_sort_body_with_big_body(self):
        big_body = {"links": {"self": "http://example.com/articles",
                              "next": "http://example.com/articles?page[offset]=2",
                              "last": "http://example.com/articles?page[offset]=10"},
                    "data": [
                        {"type": "articles",
                         "id": "1",
                         "attributes": {"title": "JSON API paints my bikeshed!"},
                         "relationships": {"author": {"links": {"self": "http://example.com/articles/1/author",
                                                                "related": "http://example.com/articles/1/author"},
                                                      "data": {"type": "people", "id": "9"}},
                                           "comments": {"links": {"self": "http://example.com/articles/1",
                                                                  "related": "http://example.com/articles"},
                                                        "data": [{"type": "comments", "id": "5"},
                                                                 {"type": "comments", "id": "12"}]}},
                         "links": {"self": "http://example.com/articles/1"}}],
                    "included": [{"type": "people", "id": "9",
                                  "attributes": {"first-name": "Dan", "last-name": "Gebhardt", "twitter": "dgeb"},
                                  "links": {"self": "http://example.com/people/9"}},
                                 {"type": "comments", "id": "5", "attributes": {"body": "First!"},
                                  "relationships": {"author": {"data": {"type": "people", "id": "2"}}},
                                  "links": {"self": "http://example.com/comments/5"}},
                                 {"type": "comments", "id": "12", "attributes": {"body": "I like XML better"},
                                  "relationships": {"author": {"data": {"type": "people", "id": "9"}}},
                                  "links": {"self": "http://example.com/comments/12"}}]}

        expected_links = ('data', [OrderedDict(
            [('attributes', OrderedDict([('title', 'JSON API paints my bikeshed!')])), ('id', 1),
             ('links', OrderedDict([('self', 'http://example.com/articles/1')])),
             ('relationships', OrderedDict([
                 ('author', OrderedDict([
                     ('data', OrderedDict([('id', 9), ('type', 'people')])),
                     ('links', OrderedDict([('related', 'http://example.com/articles/1/author'),
                                            ('self', 'http://example.com/articles/1/author')]))])),
                 ('comments', OrderedDict([('data', [OrderedDict([('id', 5), ('type', 'comments')]),
                                                     OrderedDict([('id', 12), ('type', 'comments')])]),
                                           ('links', OrderedDict([('related', 'http://example.com/articles'),
                                                                  ('self', 'http://example.com/articles/1')]))]))])),
             ('type', 'articles')])])

        expected_data = ('included', [
            OrderedDict([
                ('attributes', OrderedDict([('first-name', 'Dan'), ('last-name', 'Gebhardt'), ('twitter', 'dgeb')])),
                ('id', 9), ('links', OrderedDict([('self', 'http://example.com/people/9')])), ('type', 'people')]),
            OrderedDict([('attributes', OrderedDict([('body', 'First!')])),
                         ('id', 5),
                         ('links', OrderedDict([('self', 'http://example.com/comments/5')])),
                         ('relationships', OrderedDict([
                             ('author', OrderedDict([
                                 ('data', OrderedDict([('id', 2), ('type', 'people')]))]))])),
                         ('type', 'comments')]),
            OrderedDict([('attributes', OrderedDict([('body', 'I like XML better')])), ('id', 12),
                         ('links', OrderedDict([('self', 'http://example.com/comments/12')])),
                         ('relationships', OrderedDict([
                             ('author', OrderedDict([('data', OrderedDict([('id', 9), ('type', 'people')]))]))])),
                         ('type', 'comments')])])

        expected_included = ('links', OrderedDict([('last', 'http://example.com/articles?page[offset]=10'),
                                                   ('next', 'http://example.com/articles?page[offset]=2'),
                                                   ('self', 'http://example.com/articles')]))

        expected = OrderedDict([expected_links, expected_data, expected_included])

        # Act
        result = sort_body(big_body)

        # Assert
        self.assertEqual(result, expected)

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
        body_5 = {'var2': [5, 8, 1, 4, 6]}

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

    def test_sort_body_edge_cases_2(self):
        # Arrange
        body_1 = {'never': '{None: None}'}
        body_2 = {'gonna': {'var': '{None: [None]}'}}
        body_3 = {'give': {1: str({'None': 0})}}
        body_4 = {'unitNumber': 'A101', 'communityId': 1, 'street_address_1': '20 S 540 N',
                  'city': 'Logan', 'state': 'UT', 'zip': '12345'}
        expected_4 = OrderedDict([('city', 'Logan'), ('communityId', 1), ('state', 'UT'),
                                  ('street_address_1', '20 S 540 N'), ('unitNumber', 'A101'), ('zip', 12345)])
        body_5 = {'up': """{"array_1": "[1000, 900, 'a', 'b', 3, 'd']"}"""}
        expected_5 = OrderedDict([('up', OrderedDict([('array_1', "[1000, 900, 'a', 'b', 3, 'd']")]))])
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
        self.assertEqual(result_4, expected_4)
        self.assertEqual(result_5, expected_5)
