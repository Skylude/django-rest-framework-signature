import json
import requests

from jose import jwt

from rest_framework_signature.settings import auth_settings


def pool_url():
    aws_region = auth_settings.COGNITO_REGION
    aws_user_pool = auth_settings.COGNITO_USER_POOL
    return 'https://cognito-idp.{}.amazonaws.com/{}'.format(aws_region, aws_user_pool)


def get_client_id_from_access_token(token):
    claims = get_claims(token)
    if claims.get('token_use') != 'access':
        raise ValueError('Not an access token')
    return claims.get('client_id')


def get_claims(token, audience=None):
    # header, _, _ = get_token_segments(token)
    header = jwt.get_unverified_header(token)
    kid = header['kid']

    verify_url = pool_url()

    keys = aws_key_dict()

    key = keys.get(kid)

    kargs = {"issuer": verify_url}
    if audience is not None:
        kargs["audience"] = audience

    claims = jwt.decode(
        token,
        key,
        **kargs
    )

    return claims


def aws_key_dict():
    # todo: stash this somewhere so we dont have to fetch it everytime we auth...
    aws_data = requests.get(
        pool_url() + '/.well-known/jwks.json'
    )
    aws_jwt = json.loads(aws_data.text)

    result = {}
    for item in aws_jwt['keys']:
        result[item['kid']] = item

    return result
