from rest_framework import status
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_jwt.utils import jwt_response_payload_handler, jwt_payload_handler, jwt_encode_handler
from .renderers import UserJSONRenderer
from .serializers import (
    RegistrationSerializer, LoginSerializer, UserSerializer
)
from .models import User


class RegistrationAPIView(APIView):
    # Allow any user (authenticated or not) to hit this endpoint.
    permission_classes = (AllowAny,)
    renderer_classes = (UserJSONRenderer,)
    serializer_class = RegistrationSerializer

    def post(self, request):
        user_data = request.data
        print("User Data --->", user_data)
        serializer = self.serializer_class(data=user_data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        print(serializer.data)
        new_user = User.objects.get(email=serializer.data['email'])
        payload = jwt_payload_handler(new_user)
        token = jwt_encode_handler(payload)
        response_data = {}
        response_data['token'] = token
        response_data['data'] = serializer.data
        return Response(response_data, status=status.HTTP_201_CREATED)


class LoginAPIView(APIView):
    permission_classes = (AllowAny,)
    renderer_classes = (UserJSONRenderer,)
    serializer_class = LoginSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email') or request.user
        token = serializer.data.get('token')
        response_data = jwt_response_payload_handler(token, email, request)
        response_data['email'] = email
        return Response(response_data, status=status.HTTP_200_OK)




