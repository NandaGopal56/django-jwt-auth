from rest_framework_simplejwt import views as jwt_views
from django.urls import path, re_path
from . import views

urlpatterns = [
    path('signup', views.UserRegistrationView.as_view()),
    re_path('activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.activate_user, name='activate_user'),

    path('password_reset_request', views.password_reset_request),
    re_path('reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', views.resetPassword, name='resetPassword'),
    

    path('social_login_Google', views.social_login_Google, name="social_login_Google"),
    path('social_login_Facebook', views.social_login_Facebook, name="social_login_Facebook"),

    path('token', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'), #Obtain both Access & refresh tokens
    path('token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'), #returns new refresh token and blacklist the previos refresh token 

    path('signin', views.UserLoginView.as_view()),  #Get both tokens when credentials are correct
    path('signout', views.BlacklistRefreshView.as_view()),   #Blacklist refresh token but access token will be active


    # Test views to check access tokens working or not
    path('profile_class', views.UserProfileView_class.as_view()),
    path('profile_function', views.UserProfileView_function),
    path('admin_ProfileView_function', views.admin_ProfileView_function),
    ]
