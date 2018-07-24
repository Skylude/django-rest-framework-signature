from rest_framework_signature.models.relational import ApiEndpoint, ApiKey, ApiPermission, ApiRequestPermission, \
    CognitoUser as SignatureUser


class User(SignatureUser):
    pass
