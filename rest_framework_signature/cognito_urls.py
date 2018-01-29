from django.conf.urls import url

from rest_framework_signature import cognito_views

urlpatterns = [
    url(r'^register', cognito_views.register_user, name='register_user'),
]
