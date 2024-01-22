from django.urls import include, re_path

from test_projects.test_proj.test_app.views import ApiEndpointHandler, ApiKeyHandler, UserHandler

urlpatterns = [
    # authentication urls
    re_path(r'^auth/', include('rest_framework_signature.urls')),
    re_path(r'^apiKeys$', ApiKeyHandler.as_view()),
    re_path(r'^apiEndpoints$', ApiEndpointHandler.as_view()),
    re_path(r'^users$', UserHandler.as_view())
]
