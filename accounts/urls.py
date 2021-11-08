from rest_framework_simplejwt import views as jwt_views
from django.urls import path
from . import views

urlpatterns = [
    path('token', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('signup', views.UserRegistrationView.as_view()),
    path('signin', views.UserLoginView.as_view()),
    path('profile_class', views.UserProfileView_class.as_view()),
    path('profile_function', views.UserProfileView_function),
    ]
