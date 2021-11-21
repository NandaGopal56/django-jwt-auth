from django.shortcuts import render
from rest_framework import status
from rest_framework.generics import CreateAPIView, RetrieveAPIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
import rest_framework_simplejwt
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.decorators import authentication_classes, permission_classes, api_view
from .serializers import UserRegistrationSerializer, UserLoginSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView

from .tokens import account_activation_token
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import EmailMessage
from .models import User
from django.http import HttpResponse

class UserRegistrationView(CreateAPIView):

    serializer_class = UserRegistrationSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        send_activation_email(request, user, request.data['email'])
        status_code = status.HTTP_201_CREATED
        response = {
            'success' : True,
            'status code' : status_code,
            'message': 'User registered  successfully',
            }
        
        return Response(response, status=status_code)

def send_activation_email(request, user, email):
    print(request, user, email)
    current_site = get_current_site(request)
    mail_subject = 'Activate your blog account.'
    message = render_to_string('acc_active_email.html', {
        'user': user,
        'domain': current_site.domain,
        'uid':urlsafe_base64_encode(force_bytes(user.pk)),
        'token':account_activation_token.make_token(user),
    })
    email = EmailMessage(
                mail_subject, message, to=[email]
    )
    email.send()

def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.active = True
        user.save()
        return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
    else:
        return HttpResponse('Activation link is invalid!')


class UserLoginView(RetrieveAPIView):

    permission_classes = (AllowAny,)
    serializer_class = UserLoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        response = {
            'success' : 'True',
            'status code' : status.HTTP_200_OK,
            'message': 'User logged in  successfully',
            'access_token': serializer.data['access_token'],
            'refresh_token': serializer.data['refresh_token']
            }
        status_code = status.HTTP_200_OK

        return Response(response, status=status_code)


#Blacklist refresh token
class BlacklistRefreshView(APIView): 

    permission_classes = (IsAuthenticated,)
    authentication_class = JWTAuthentication
    
    def post(self, request):
        try:
            token = RefreshToken(request.data.get('refresh'))
            token.blacklist()
            return Response("Success")
        except rest_framework_simplejwt.exceptions.TokenError:
            return Response("Token is blacklisted")


class UserProfileView_class(RetrieveAPIView):

    permission_classes = (IsAuthenticated,)
    authentication_class = JWTAuthentication

    def get(self, request):
        try:
            user_profile = request.user
            status_code = status.HTTP_200_OK
            response = {
                'success': True,
                'status code': status_code,
                'message': 'User profile fetched successfully',
                'data': [{
                    'first_name': user_profile.first_name,
                    'last_name': user_profile.last_name,
                    'email': user_profile.email,
                    }]
                }

        except Exception as e:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                'success': False,
                'status code': status.HTTP_400_BAD_REQUEST,
                'message': 'User does not exists',
                'error': str(e)
                }
        return Response(response, status=status_code)

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def UserProfileView_function(request, format=None):
    try:
        user_profile = request.user
        status_code = status.HTTP_200_OK
        response = {
            'success': True,
            'status code': status_code,
            'message': 'User profile fetched successfully',
            'data': [{
                'first_name': user_profile.first_name,
                'last_name': user_profile.last_name,
                'email': user_profile.email,
                }]
            }
    except Exception as e:
        status_code = status.HTTP_400_BAD_REQUEST
        response = {
            'success': False,
            'status code': status.HTTP_400_BAD_REQUEST,
            'message': 'User does not exists',
            'error': str(e)
            }
    return Response(response, status=status_code)