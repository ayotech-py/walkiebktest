import os
from rest_framework.authentication import BaseAuthentication
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed


class ApiKeyAuthentication(BaseAuthentication):
    def authenticate(self, request):
        api_key = request.headers.get("ApiAuthorization")

        if not api_key:
            raise AuthenticationFailed("Please provide an API key")

        api_key = api_key.replace("Api-Key ", "")
        API_KEY = settings.API_KEY

        if api_key == API_KEY:
            return None, None
        else:
            raise AuthenticationFailed("Invalid API key")
