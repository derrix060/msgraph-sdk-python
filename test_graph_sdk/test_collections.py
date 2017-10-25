import unittest
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

import msgraph
from msgraph import HttpResponse
from msgraph import ChildrenCollectionPage, ChildrenCollectionRequest
from msgraph import Folder
import json


class TestCollections(unittest.TestCase):

    @patch('msgraph.HttpProvider')
    @patch('msgraph.AuthProvider')
    def test_page_creation(self, MockHttpProvider, MockAuthProvider):
        """
        Test page creation when there is no nextLink attached to the collection
        """
        response = HttpResponse(200, None, json.dumps({"value":[{"name":"test1", "folder":{}}, {"name":"test2"}]}))

        instance = MockHttpProvider.return_value
        instance.send.return_value = response

        instance = MockAuthProvider.return_value
        instance.authenticate.return_value = "blah"
        instance.authenticate_request.return_value = None

        http_provider = msgraph.HttpProvider()
        auth_provider = msgraph.AuthProvider()
        client = msgraph.GraphClient("graphurl/", http_provider, auth_provider)

        items = client.drives["me"].items["root"].children.request().get()

        assert len(items) == 2
        assert type(items) is ChildrenCollectionPage
        assert items[0].name == "test1"
        assert type(items[0].folder) is Folder
        assert items[1].folder is None

    @patch('msgraph.HttpProvider')
    @patch('msgraph.AuthProvider')
    def test_paging(self, MockHttpProvider, MockAuthProvider):
        """
        Test paging of a file in situations where more than one page is available
        """
        response = HttpResponse(200, None, json.dumps({"@odata.nextLink":"testing", "value":[{"name":"test1", "folder":{}}, {"name":"test2"}]}))

        instance = MockHttpProvider.return_value
        instance.send.return_value = response

        instance = MockAuthProvider.return_value
        instance.authenticate.return_value = "blah"
        instance.authenticate_request.return_value = None

        http_provider = msgraph.HttpProvider()
        auth_provider = msgraph.AuthProvider()
        client = msgraph.GraphClient("graphurl/", http_provider, auth_provider)

        items = client.drives["me"].items["root"].children.request().get()

        assert type(items.next_page_request) is ChildrenCollectionRequest
        assert type(items.next_page_request.get()) is ChildrenCollectionPage

if __name__ == '__main__':
    unittest.main()