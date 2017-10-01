from django.conf.urls import url

from rest_framework_signature import views as authentication_views

urlpatterns = [
    url(r'^check_password_reset_link', authentication_views.check_password_reset_link, name='check_password_reset_link'),
    url(r'^login$', authentication_views.obtain_auth_token, name='login'),
    url(r'^logout$', authentication_views.delete_auth_token, name='logout'),
    url(r'^ping', authentication_views.ping, name='ping'),
    url(r'^reset_password$', authentication_views.reset_password, name='reset_password'),
    url(r'^sso_login$', authentication_views.obtain_auth_token_sso, name='loginSSO'),
    url(r'^submit_new_password', authentication_views.submit_new_password, name='submit_new_password')
]
