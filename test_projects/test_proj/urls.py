from django.conf.urls import include, url

from test_projects.test_proj.test_app.views import ApiKeyHandler, UserHandler

urlpatterns = [
    # authentication urls
    url(r'^auth/', include('rest_framework_signature.urls')),
    url(r'^apiKeys$', ApiKeyHandler.as_view()),
    url(r'^users$', UserHandler.as_view())
]
