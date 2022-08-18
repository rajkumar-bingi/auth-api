import imp
from os import write
from re import U
from tkinter.ttk import Style
from unittest.util import _MAX_LENGTH
from rest_framework import serializers
from account.models import User


class UserRegistrationSerializer(serializers.ModelSerializer):
    # we are writing this because we need to confirm password field in Registration request.
    password2 = serializers.CharField(
        style={'input_field': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'name', 'password', 'password2', 'tc']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    # validating password and confirm password while registration:
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError(
                'password and confirm password does not match!')
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ['email', 'password']
