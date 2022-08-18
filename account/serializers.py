from multiprocessing.sharedctypes import Value
from xml.dom import ValidationErr
from rest_framework import serializers
from account.models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator


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


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'email']


class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        style={'input_field': 'password'}, write_only=True)
    password2 = serializers.CharField(
        style={'input_field': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get("user")
        if password != password2:
            raise serializers.ValidationError(
                'password and confirm password does not match!')
        user.set_password(password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ["email"]

    def validate(self, attrs):
        email = attrs.get("email")
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print("encoded ", uid)

            token = PasswordResetTokenGenerator().make_token(user)
            print("reset token ", token)

            link = 'http://localhost:3000/api/user/reset/'+uid+'/'+token
            print("password reset link ", link)
            return attrs
        else:
            raise ValidationErr("You are not a Registered user")
