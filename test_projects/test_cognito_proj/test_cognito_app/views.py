from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_signature import authentication

from test_projects.test_cognito_proj.test_cognito_app.models import ApiKey


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