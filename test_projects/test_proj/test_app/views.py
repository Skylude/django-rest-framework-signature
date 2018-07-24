from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_signature import authentication

from test_projects.test_proj.test_app.models import *


class ApiEndpointHandler(APIView):
    authentication_classes = (authentication.TokenAuthentication,)
    permission_classes = ()

    def post(self, request):
        api_endpoint = ApiEndpoint(endpoint=request.data.get('endpoint', None))
        api_endpoint.save()
        return Response(api_endpoint.endpoint)


class ApiKeyHandler(APIView):
    """
    View to list all api keys in the system.
    """
    authentication_classes = (authentication.TokenAuthentication,)
    permission_classes = ()

    def get(self, request, format=None):
        """
        Return a list of all users.
        """
        api_keys = [api_key.name for api_key in ApiKey.objects.all()]
        return Response(api_keys)


class UserHandler(APIView):
    """
    View to list all api keys in the system.
    """
    authentication_classes = (authentication.TokenAuthentication,)
    permission_classes = ()

    def get(self, request, format=None):
        """
        Return a list of all users.
        """
        users = [user.username for user in User.objects.all()]
        return Response(users)
