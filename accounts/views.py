from django.contrib import auth
from django.http.response import JsonResponse
from django.shortcuts import render
from rest_framework import status
from rest_framework.generics import CreateAPIView, RetrieveAPIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
import rest_framework_simplejwt
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.decorators import authentication_classes, permission_classes, api_view
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import EmailMessage
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.conf import settings
import requests, json
from .tokens import password_reset_token, account_activation_token
from .models import User, SocialAuthenticatedUsers
from .forms import UserPasswordResetForm
from .serializers import UserRegistrationSerializer, UserLoginSerializer
from django.contrib.auth.models import update_last_login

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
    email.content_subtype = "html"
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


@api_view(["POST"])
@permission_classes([AllowAny])
def password_reset_request(request):
    """User forgot password form view."""
    if request.method == "POST":
        email = request.data.get("email")
        qs = User.objects.filter(email=email)
        site = get_current_site(request)
        if len(qs) > 0:
            user = qs[0]
            user.active = False  # User needs to be inactive for the reset password duration
            user.save()
            mail_subject = f'Reset password for {site.domain}'
            message = render_to_string('password_reset_mail.html', {
                'user': user,
                'domain': site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })
            email = EmailMessage(
                            mail_subject, message, to=[email]
                )
            email.content_subtype = "html"
            email.send()
        else:
            return HttpResponse('User does not exist with this email !', status=400)
        return HttpResponse('Password reset email sent')



@api_view(["GET", "POST"])
@permission_classes([AllowAny])
def resetPassword(request, uidb64, token):
    if request.method == 'POST':
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
                try:
                    form.save()
                    update_session_auth_hash(request, form.user)
                    user.active = True
                    user.save()
                    return HttpResponse('Password reset successfull !!')
                except Exception as e:
                    return HttpResponse('Sorry, something went wrong. Please try agaiin or contact us.', status=400)
            else:
                return HttpResponse('Sorry, Password reset unsuccessfull, Please check the required conditions to set password !!', status=400)
        else:
            return HttpResponse('Password reset link is invalid. Please request a new password reset. !!', status=400)
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
        return HttpResponse('Password reset link is invalid. Please request a new password reset. !!', status=400)



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


@api_view(["POST"])
@permission_classes([AllowAny])
def social_login_Google(request):
    code = request.data.get("code")
    data =  {
                "code": code,
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                "grant_type": settings.GOOGLE_GRANT_TYPE
            }
    headers = {'Content-type': 'application/json'}
    authenticationTokens = requests.post(settings.GOOGLE_GET_TOKENS_URL, data=json.dumps(data), headers=headers).json()
    
    if 'error' in authenticationTokens:
        errorResponse = {
            'success': False,
            'message': "Something went wrong. Please try again.",
            'extra_message': authenticationTokens['error_description']
        }
        return JsonResponse(errorResponse, status=400)

    userInfo = requests.get(url = settings.GOOGLE_GET_USERINFO_URL, params = {'access_token': authenticationTokens['access_token']}).json()

    try:
        user = User.objects.get(google_ID=userInfo["id"])
        
        message = "You are signed in successfully"
        
        if userInfo['email'] == user.get_user_email():
            #emails are same, no actions needed
            pass
        else:
            #The email of the social account has been changed as compared to our data:- so update it
            obj = SocialAuthenticatedUsers.objects.get(google_ID = userInfo['id'])  
            obj.email = userInfo['email']
            obj.save()

    except User.DoesNotExist:
        user = User.objects.create_user(email = userInfo['email'],
            first_name = userInfo['name'],
            last_name = userInfo['family_name'],
            google_ID = userInfo['id'],
            source_provider = "Google",
            source = "social",
            is_active = True)
        message = "Your account is setup successfully with Google"

    access_token, refresh_token = get_JWT_tokens_Social_login(user)
    response = {
            'success' : True,
            'status code' : status.HTTP_200_OK,
            'message': message,
            'access_token': access_token,
            'refresh_token': refresh_token
            }
    return Response(response, status=status.HTTP_200_OK)



@api_view(["POST"])
@permission_classes([AllowAny])
def social_login_Facebook(request):
    code = request.data.get("code")
    signUP = True
    params =  {
                "client_id": settings.FACEBOOK_CLIENT_ID,
                "redirect_uri": settings.FACEBOOK_REDIRECT_URI,
                "client_secret": settings.FACEBOOK_CLIENT_SECRET,
                "code": code,
            }
    headers = {'Content-type': 'application/json'}
    authenticationTokens = requests.get(settings.FACEBOOK_GET_TOKENS_URL, params=params, headers=headers).json()
    
    if 'error' in authenticationTokens:
        errorResponse = {
            'success': False,
            'message': "Something went wrong. Please try again.",
            'extra_message': authenticationTokens['error']['message']
        }
        return JsonResponse(errorResponse, status=400)
    
    userInfo = requests.get(url = settings.FACEBOOK_GET_USERINFO_URL, params = {'access_token': authenticationTokens['access_token']}).json()

    try:
        user = User.objects.get(facebook_ID=userInfo["id"])
        
        message = "You are signed in successfully"
        
        if userInfo['email'] == user.get_user_email():
            #emails are same, no actions needed
            pass
        else:
            #The email of he social account has been changed as compared to our data:- so update it
            obj = SocialAuthenticatedUsers.objects.get(facebook_ID = userInfo['id'])  
            obj.email = userInfo['email']
            obj.save()

    except User.DoesNotExist:
        user = User.objects.create_user(email = userInfo['email'],
            first_name = userInfo['name'],
            last_name = userInfo['name'],
            facebook_ID = userInfo['id'],
            source_provider = "Facebook",
            source = "social",
            is_active = True)
        message = "Your account is setup successfully with Google"

    access_token, refresh_token = get_JWT_tokens_Social_login(user)
    response = {
            'success' : True,
            'status code' : status.HTTP_200_OK,
            'message': message,
            'access_token': access_token,
            'refresh_token': refresh_token
            }
    return Response(response, status=status.HTTP_200_OK)


def get_JWT_tokens_Social_login(user):
    access_token = str(RefreshToken.for_user(user).access_token)
    refresh_token = str(RefreshToken.for_user(user))
    update_last_login(None, user)
    return access_token, refresh_token





















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
                    'email': user_profile.get_user_email(),
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
                'email': user_profile.get_user_email(),
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

from .permissions import IsAdmin
@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdmin])
def admin_ProfileView_function(request, format=None):
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
                'email': user_profile.get_user_email(),
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