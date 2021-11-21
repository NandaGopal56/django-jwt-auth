from django.contrib.messages import api
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
    mail_subject = f'Activate your account with {current_site.domain}'
    message = render_to_string('account_activateion.html', {
        'user': user,
        'domain': current_site.domain,
        'uid':urlsafe_base64_encode(force_bytes(user.pk)),
        'token':account_activation_token.make_token(user),
    })
    email = EmailMessage(
                mail_subject, message, to=[email]
    )
    email.send()

def activate_user(request, uidb64, token):
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

from .forms import UserPasswordResetForm
from django.contrib import messages
from .tokens import password_reset_token
from django.contrib.auth import update_session_auth_hash



@api_view(["POST"])
@permission_classes([AllowAny])
def password_reset_request(request):
    """User forgot password form view."""
    if request.method == "POST":
        email = 'ngopal561998@gmail.com'
        print(request.POST)
        print(email)
        qs = User.objects.filter(email=email)
        site = get_current_site(request)
        if len(qs) > 0:
            user = qs[0]
            user.active = False  # User needs to be inactive for the reset password duration
            user.save()
            print(user)

            mail_subject='Reset password for domain.com'
            message = render_to_string('password_reset_mail.html', {
                'user': user,
                'domain': site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })
            email = EmailMessage(
                            mail_subject, message, to=[email]
                )
            email.send()

        messages.add_message(request, messages.SUCCESS, 'Email {0} submitted.'.format(email))
        msg = 'If this mail address is known to us, an email will be sent to your account.'
    else:
        messages.add_message(request, messages.WARNING, 'Email not submitted.')
        return HttpResponse('Email is not present with us!')

    return HttpResponse('Password reset email sent')



@api_view(["GET", "POST"])
@permission_classes([AllowAny])
def resetPassword(request, uidb64, token):
    if request.method == 'POST':
        print("---------reset password POST method to update password-----------")
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            print(user)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
            messages.add_message(request, messages.WARNING, str(e))
            user = None

        if user is not None and password_reset_token.check_token(user, token):
            form = UserPasswordResetForm(user=user, data=request.POST)
            print(form)
            if form.is_valid():
                print("form is valid")
                try:
                    form.save()
                    update_session_auth_hash(request, form.user)
                    user.active = True
                    user.save()
                    messages.add_message(request, messages.SUCCESS, 'Password reset successfully.')
                    return HttpResponse('Password reset successfull !!')
                except Exception as e:
                    print("unsuccessfull:...", str(e))
            else:
                return HttpResponse('Sorry, Password reset unsuccessfull !!')
        else:
            messages.add_message(request, messages.WARNING, 'Password reset link is invalid.')
            messages.add_message(request, messages.WARNING, 'Please request a new password reset.')

    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
        messages.add_message(request, messages.WARNING, str(e))
        user = None

    if user is not None and password_reset_token.check_token(user, token):
        context = {
            'form': UserPasswordResetForm(user),
            'uid': uidb64,
            'token': token,
            'valid': True
        }
        return render(request, 'password_reset_conf.html', context)
    else:
        messages.add_message(request, messages.WARNING, 'Password reset link is invalid.')
        messages.add_message(request, messages.WARNING, 'Please request a new password reset.')

    return HttpResponse('Password reset link is invalid.')














class UserLoginView(RetrieveAPIView):

    permission_classes = (AllowAny,)
    serializer_class = UserLoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        response = {
            'success' : True,
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