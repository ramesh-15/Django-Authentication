
from django.urls import path
from .views import UserRegistrationView, UserLoginView,UserProfileUpdateView,UserListView,ChangePasswordView
from django.conf import settings
from django.conf.urls.static import static
urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileUpdateView.as_view(), name='profile'),
    path('users/', UserListView.as_view(), name='user-list'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
]

