from rest_framework import serializers
from rest_framework_jwt.utils import jwt_payload_handler, jwt_encode_handler
from .models import User
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate


class RegistrationSerializer(serializers.ModelSerializer):
    """Serializers registration requests and creates a new user."""
    # Ensure passwords are at least 8 characters long, no longer than 25
    # characters, and can not be read by the client.
    password = serializers.CharField(
        max_length=25,
        min_length=8,
        write_only=True
    )

    class Meta:
        model = User
        fields = ["email", "username", "password", "contact_no", "firstname", "lastname"]

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class LoginSerializer(serializers.Serializer):

    email = serializers.CharField(max_length=255)
    username = serializers.CharField(max_length=255, read_only=True)
    password = serializers.CharField(max_length=255, write_only=True)
    token = serializers.CharField(max_length=255, read_only=True)

    def validate(self, attrs):
        email = attrs.get("email", None)
        password = attrs.get("password", None)

        if email is None:
            raise serializers.ValidationError("Email address is required to login")
        if password is None:
            raise serializers.ValidationError("Password is required to login")

        user = authenticate(username=email, password=password)
        if user is None:
            raise serializers.ValidationError(
                'A user with this email and password was not found.'
            )
        if not user.is_active:
            raise serializers.ValidationError(
                'This user has been deactivated.'
            )
        payload = jwt_payload_handler(user)
        return {
            'token': jwt_encode_handler(payload),
            'email': email,
        }


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=25,
        min_length=8,
        write_only=True
    )

    class Meta:
        model = User
        fields = ("email", "username", "passwprd")

    def update(self, instance, validated_data):
        password = validated_data.pop("password", None)
        for key, value in validated_data.items():
            setattr(instance, key, value)

        if password is not None:
            instance.set_password(password)

        instance.save()
        return instance

