from django.urls import path
from .views import *

urlpatterns = [
    path('user/signup-page/', UserSignupPageView.as_view(), name='user-signup-page'),
    path('user/login-page/', UserLoginPageView.as_view(), name='user-login-page'),
    path('user/dashboard/', UserDashboardPageView.as_view(), name='user-dashboard-page'),

    
]
