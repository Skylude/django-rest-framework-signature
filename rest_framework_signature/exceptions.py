from rest_framework.exceptions import APIException
from rest_framework import status


class InvalidAuthSettings(Exception):
    def __init__(self, message):
        # Call the base class constructor with the parameters it needs
        super(InvalidAuthSettings, self).__init__(message)


class SignatureException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
