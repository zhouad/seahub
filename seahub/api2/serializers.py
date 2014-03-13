from rest_framework import serializers

from seahub.auth import authenticate
from seahub.api2.models import TokenV2

class AuthTokenSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(username=username, password=password)

            if user:
                if not user.is_active:
                    raise serializers.ValidationError('User account is disabled.')
                attrs['user'] = user
                return attrs
            else:
                raise serializers.ValidationError('Unable to login with provided credentials.')
        else:
            raise serializers.ValidationError('Must include "username" and "password"')

class AuthTokenV2Serializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
    platform = serializers.CharField()
    device_name = serializers.CharField()

    client_version = serializers.CharField()
    platform_version = serializers.CharField()

    def validate(self, attrs):
        username = attrs.get('username', None)
        password = attrs.get('password', None)
        platform = attrs.get('platform', None)
        device_name = attrs.get('device_name', None)
        client_version = attrs.get('client_version', '')
        platform_version = attrs.get('platform_version', '')

        # if not (username and password and platform and device_name and client_version and platform_version):
        if not (username and password and platform and device_name):
            raise serializers.ValidationError('param must not be null')

        user = authenticate(username=username, password=password)
        if user is None or not user.is_active:
            raise serializers.ValidationError('Unable to login with provided credentials.')

        token_obj = TokenV2(user=username,
                            device_name=device_name,
                            platform=platform,
                            client_version=client_version,
                            platform_version=platform_version)

        token_obj.save()

        attrs['token'] = token_obj.token

        return attrs

class AccountSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    is_staff = serializers.BooleanField(default=False)
    is_active = serializers.BooleanField(default=True)
