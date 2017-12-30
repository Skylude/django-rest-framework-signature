from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_signature import authentication


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
