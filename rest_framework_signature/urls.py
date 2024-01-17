from django.urls import re_path

from rest_framework_signature import views as authentication_views

urlpatterns = [
    re_path(r'^check_password_reset_link', authentication_views.check_password_reset_link, name='check_password_reset_link'),
    re_path(r'^login$', authentication_views.obtain_auth_token, name='login'),
    re_path(r'^logout$', authentication_views.delete_auth_token, name='logout'),
    re_path(r'^ping', authentication_views.ping, name='ping'),
    re_path(r'^reset_password$', authentication_views.reset_password, name='reset_password'),
    re_path(r'^sso_login$', authentication_views.obtain_auth_token_sso, name='loginSSO'),
    re_path(r'^submit_new_password', authentication_views.submit_new_password, name='submit_new_password')
]
