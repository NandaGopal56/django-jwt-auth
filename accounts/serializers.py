from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User

class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('email', 'password', 'first_name', 'last_name',)
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

class UserLoginSerializer(serializers.Serializer):

    email = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=128, write_only=True)
    access_token = serializers.CharField(max_length=255, read_only=True)
    refresh_token = serializers.CharField(max_length=255, read_only=True)

    def validate(self, data):
        email = data.get("email", None)
        password = data.get("password", None)
        user = authenticate(email=email, password=password)
        print("user: ", user)
        if user is None:
            raise serializers.ValidationError(
                'Please check the email id and password again !'
            )
        try:
            access_token = str(RefreshToken.for_user(user).access_token)
            refresh_token = str(RefreshToken.for_user(user))
            update_last_login(None, user)
        except User.DoesNotExist:
            raise serializers.ValidationError(
                'Please check the email id and password again !'
            )
        return {
            'email': user.email,
            'access_token': access_token,
            'refresh_token': refresh_token
        }
