# Rest Framework Signature

This adds signature authentication to Django / Rest Framework. In addition it provides an easy to use password reset module apart from Django's built in.

### Breaking Changes
4.0.0.dev1 Migrated the project for Django 4.2 and newer
1.4.0.dev1 Moved full access key and bypass auth users to the database. You will need to update your models to utilize this. Older settings will still work. One requirement with this new build is to add API_ENDPOINT_MODEL to your settings for more streamlined testing.
1.3.0.dev1 Migrated to DjangoTestCase under the hood so when moving to this version you'll need to revisit your tests
1.2.0.de 1 When updating past this version you will be required to send in an APIRequetPermission model
1.0.4.dev1 When updating past this version you will be required to install the following pip packages: python-jose

### WINDOWS REQUIREMENTS
In order to build in Windows environments you need to have the C++ compiler installed. This can be done within Visual Studio 2015 by installing the Visual C++ tools for Windows

## Testing
### Run tests with manage.py
To run tests in test projects:
```
cd test_projects/test_proj
python manage.py test test_projects.test_proj.test_app
```

If you want to run tests from the root project directory, you can use the following commands:

```bash
python -m unittest discover -s test_projects/test_proj/ -p '*tests.py'
python -m unittest discover -s rest_framework_signature/ -p '*tests.py'
```

### Run tests without manage.py
If you are debugging or running them without manage.py you need to create the databases:
 * drfsig for test_proj

You then need to run migrations
```
cd test_projects/test_proj
python manage.py migrate
```

Then you will be able to run / debug tests and code!

## SETTINGS

### AUTH_TOKEN_EXPIRATION
##### Default is 168 / This setting is in hours
This is how long authentication tokens will be valid


### RESET_PASSWORD_TOKEN_EXPIRATION
##### Default is 1 / This setting is in hours
This is how long a password reset token is good for


### FAILED_LOGIN_FREEZE_TIME
##### Default is 20 / This setting is in minutes
When a user fails to login a certain number of times they will be locked out for this period of time


### FAILED_LOGIN_RETRY_ATTEMPTS
##### Default is 20
This is how many times someone can fail to login / authenticate before their account is locked


### USER_DOCUMENT
This is the model that is passed in and used for the User model. This is the user model that will be used within Django. This has the following required fields:
 * first_name: CharField
 * last_name: CharField
 * username: CharField
 * salt: CharField
 * password_reset_token: CharField
 * updated: DateTimeField
 * created: DateTimeField
 * is_active: BooleanField


### AUTH_TOKEN_DOCUMENT
This is the model that is utilized for the AuthToken model. This is an auth token for a specific user so you can tie each API call to a specific logged in user. This has the following required fields:
 * key: CharField
 * user: ForeignKey to the USER_DOCUMENT
 * auth_type: CharField


### APPLICATION_DOCUMENT
This is the model that is utilized for the Application model. This is the ApiKey model which is used to give different applications access to the API.


### API_PERMISSION_MODEL
This is the model that is used to restrict and grant access to each individual endpoint in your API. This has the following required fields on the model:


### API_REQUEST_PERMISSION_MODEL
This is the model that is used to restrict and grant access to each individual endpoint with specific request variables. This has the following required fields on the model:
* api_key: ForeignKey field to the APPLICATION_DOCUMENT setting
* api_endpoint: ForeignKey field to the ApiEndpoint model defined in relational.py
* request_key: CharField containing the key in the request.data dictionary that you want to restrict access on
* request_value: CharField containing the value in the request_key that you watn to restrict access on

### API_ENDPOINT_MODEL
This is the model that is used to link into the API_REQUEST_PERMISSION table that has the endpoint data. This was not used until version 1.4.0.
* endpoint: Endpoint in the shortened django url form i.e. ^/users$ (can be a regex)


### DB_SETTINGS
This setting is utilized when mongo is the underlying engine. We have to connect to the mongo database and need to utilize DB_SETTINGS field to initialize the connection to the database.


### SUPER_KEY_AUTH
This can be set on development and local environments to easily test without providing authentication credentials or an API key. Should not be set on production.


### SUPER_KEY_HEADER
##### Default undefined as SUPER_KEY_AUTH is not enabled by default
Name of the header you would like for SUPER_KEY_AUTH usually something like HTTP_X_DRFSIG_SUPER_KEY


### TIMESTAMP_HEADER
##### Default HTTP_X_DRFSIG_TIMESTAMP
Name of header containing timestamp


### NONCE_HEADER
##### Default HTTP_X_DRFSIG_NONCE
Name of header containing the nonce


### API_KEY_HEADER
##### Default HTTP_X_DRFSIG_API_KEY
Name of header containing the api key public key


### DATABASE_ENGINE
This tells authentication which underlying DB we are using. Currently there is mongo, and mssql as options. mssql is the setting to use for any approved Django relational database.


### REPLAY_ATTACK_TIME
##### Default 60000 / This is in milliseconds
This is the amount of time a request with it's associated nonce is good for until it is expired. This will prevent replay attacks on endpoints.


### DISABLE_USER_AUTH
##### Default is False
This setting will disable the requirement of having a user authenticated with each request.


### BYPASS_URLS
This setting is for URLS that can bypass user authentication / api keys. There are times when you need to submit certain requests and do not have a user logged in.

### BYPASS_USER_AUTH_API_KEY_NAMES ###
This setting is for Api Keys you want to use that do not utilize user authentication but still need access to specific endpoints and you don't wnat to add them all the BYPASS_URLS

### UNSECURED_URLS
This setting is for URLS that do not need an ApiKey OR an authenticated user. They should be used sparingly and the usual suspects for this is some ping endpoint to check uptime.


### SSO_TOKEN_CLASSES
This setting is to define classes that will utilize an SSO token and allow users to login using a one time token. It will take a list of classes with the following required fields:
 * token: CharField
 * user: ForeignKey to the USER_DOCUMENT


### FULL_ACCESS_API_KEY_NAMES
This setting is to allow full access to all endpoints so you do not need to create an API Permission for each endpoint for the main applications that utilize your API.


### MULTIPART_POST_URLS
This setting identifies endpoints that are multipart post urls. Authentication is currently handled differently for them as it is a little trickier to calculate the nonce.
