from rest_framework_simplejwt import views as jwt_views
from django.urls import path
from . import views

urlpatterns = [
    path('signup', views.UserRegistrationView.as_view()),
    path('activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.activate_user, name='activate_user'),

    path('password_reset_request', views.password_reset_request),
    path('reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', views.resetPassword, name='resetPassword'),
    

    path('social_login_Google', views.social_login_Google, name="social_login_Google"),
    # path('social_login_Google', views.social_login_Google, name="social_login_Google"),

    path('token', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'), #Obtain both Access & refresh tokens
    path('token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'), #returns new refresh token and blacklist the previos refresh token 
    path('signin', views.UserLoginView.as_view()),
    path('signout', views.BlacklistRefreshView.as_view()),   #Blacklist refresh token



    path('profile_class', views.UserProfileView_class.as_view()),
    path('profile_function', views.UserProfileView_function),
    ]
