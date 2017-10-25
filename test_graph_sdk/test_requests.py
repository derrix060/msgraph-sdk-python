import unittest
try:
    from unittest.mock import patch, Mock
except ImportError:
    from mock import patch, Mock

try:
    from urllib.parse import urlparse, parse_qsl
except:
    from urlparse import urlparse, parse_qsl

import msgraph
from msgraph import GraphError, ErrorCode
from msgraph import HttpResponse
from msgraph import ItemReference
from msgraph import ItemDeltaCollectionPage
from msgraph import ItemDeltaRequest
import time
import json


class TestRequests(unittest.TestCase):

    @patch('msgraph.HttpProvider')
    @patch('msgraph.AuthProvider')
    def test_path_creation(self, MockHttpProvider, MockAuthProvider):
        """
        Tests that the path of a request is resolved correctly
        """
        http_provider = msgraph.HttpProvider()
        auth_provider = msgraph.AuthProvider()
        client = msgraph.GraphClient("graphurl/", http_provider, auth_provider)

        request = client.drives["me"].items["root"].children.request()
        assert request.request_url == "graphurl/drives/me/items/root/children"

        request = client.drives["me"].items["root"].children["testfile.txt"].request()
        assert request.request_url == "graphurl/drives/me/items/root/children/testfile.txt"

    @patch('msgraph.HttpProvider')
    @patch('msgraph.AuthProvider')
    def test_path_creation_with_query(self, MockHttpProvider, MockAuthProvider):
        """
        Tests that a path is created with the correct query parameters
        """
        http_provider = msgraph.HttpProvider()
        auth_provider = msgraph.AuthProvider()
        client = msgraph.GraphClient("graphurl/", http_provider, auth_provider)

        request = client.drives["me"].items["root"].children.request(top=3, select="test")

        query_dict = dict(parse_qsl(urlparse(request.request_url).query))
        expected_dict = {"select":"test", "top":"3"}
        assert all(item in query_dict.items() for item in expected_dict.items())

    @patch('msgraph.HttpProvider')
    @patch('msgraph.AuthProvider')
    def test_method_body_format(self, MockHttpProvider, MockAuthProvider):
        """
        Test that the parameters are correctly entered into the body of the message
        of methods that require this
        """
        http_provider = msgraph.HttpProvider()
        auth_provider = msgraph.AuthProvider()
        client = msgraph.GraphClient("graphurl/", http_provider, auth_provider)

        ref = ItemReference()
        ref.id = "testing!id"

        copy_request = client.drives["me"].items["testitem!id"].copy(parent_reference=ref, name="newName").request()
        assert copy_request.request_url == "graphurl/drives/me/items/testitem!id/action.copy"

        expected_dict = {"parentReference": {"id":"testing!id"}, "name":"newName"}
        assert all(item in copy_request.body_options.items() for item in expected_dict.items())

    @patch('msgraph.HttpProvider')
    @patch('msgraph.AuthProvider')
    def test_method_query_format(self, MockHttpProvider, MockAuthProvider):
        """
        Test that the parameters are correctly entered into the query string
        of the request for methods that require this
        """
        http_provider = msgraph.HttpProvider()
        auth_provider = msgraph.AuthProvider()
        client = msgraph.GraphClient("graphurl/", http_provider, auth_provider)

        changes_request = client.drives["me"].items["testitem!id"].delta(token="token").request()
        assert urlparse(changes_request.request_url).path == "graphurl/drives/me/items/testitem!id/view.delta"

        query_dict = dict(parse_qsl(urlparse(changes_request.request_url).query))
        expected_dict = {"token":"token"}
        assert all(item in query_dict.items() for item in expected_dict.items())

    @patch('msgraph.HttpProvider')
    @patch('msgraph.AuthProvider')
    def test_polling_background_method(self, MockHttpProvider, MockAuthProvider):
        """
        Test that polling in the background actually functions as it should and polls
        on a seperate thread.
        """
        response = HttpResponse(301, {"Location": "statusLocation"}, "")
        instance_http = MockHttpProvider.return_value
        instance_http.send.return_value = response

        instance_auth = MockAuthProvider.return_value
        instance_auth.authenticate.return_value = "blah"
        instance_auth.authenticate_request.return_value = None

        http_provider = msgraph.HttpProvider()
        auth_provider = msgraph.AuthProvider()
        client = msgraph.GraphClient("graphurl/", http_provider, auth_provider)

        ref = ItemReference()
        ref.id = "testing!id"
        mock = Mock()

        copy_operation = client.drives["me"].items["testitem!id"].copy(parent_reference=ref, name="newName").request().post()

        response = HttpResponse(200, None, json.dumps({"operation":"copy", "percentageComplete":0, "status": "In progress"}))
        instance_http.send.return_value = response

        time.sleep(0.2)

        assert copy_operation.item is None

        response = HttpResponse(200, None, json.dumps({"id" : "testitem!id", "name": "newName"}))
        instance_http.send.return_value = response

        time.sleep(0.1)

        assert copy_operation.item is not None

    @patch('msgraph.HttpProvider')
    @patch('msgraph.AuthProvider')
    def test_method_collections(self, MockHttpProvider, MockAuthProvider):
        """
        Test that collections are returned properly from method calls that return collections
        """
        response = HttpResponse(200, None, json.dumps({"@odata.nextLink":"testing", "value":[{"name":"test1", "folder":{}}, {"name":"test2"}]}))

        instance = MockHttpProvider.return_value
        instance.send.return_value = response

        instance = MockAuthProvider.return_value
        instance.authenticate.return_value = "blah"
        instance.authenticate_request.return_value = None

        http_provider = msgraph.HttpProvider()
        auth_provider = msgraph.AuthProvider()
        client = msgraph.GraphClient("graphurl", http_provider, auth_provider)

        items = client.drives["me"].items["testitem!id"].delta().request().get()
        assert type(items.next_page_request) is ItemDeltaRequest
        assert type(items.next_page_request.get()) is ItemDeltaCollectionPage

    @patch('msgraph.HttpProvider')
    @patch('msgraph.AuthProvider')
    def test_error(self, MockHttpProvider, MockAuthProvider):
        """
        Test that the error is thrown and can be correctly handled
        """
        try:
            response = HttpResponse(404, None, json.dumps({"error":{"code":"itemNotFound", "message":"The resource could not be found"}}))
            assert False
        except GraphError as e:
            assert e.status_code == 404
            assert e.code == ErrorCode.ItemNotFound

        try:
            response = HttpResponse(403, None, json.dumps({"error":{"code":"generalException", "message":"TestMessage", "innererror":{"code":"accessDenied", "message":"TestMessage", "innererror":{"code":"unauthenticated", "message":"TestMessage"}}}}))
            assert False
        except GraphError as e:
            assert e.status_code == 403
            assert e.code == ErrorCode.GeneralException
            assert e.matches(ErrorCode.AccessDenied)
            assert e.matches(ErrorCode.Unauthenticated)
            assert not e.matches(ErrorCode.NotSupported)

if __name__ == '__main__':
    unittest.main()
