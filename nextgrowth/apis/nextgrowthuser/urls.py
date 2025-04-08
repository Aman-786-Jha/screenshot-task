from django.urls import path
from .views import DefaultUserSignupView, DefaultUserLoginView, UserLogoutView
from . import views 
from .views import *

urlpatterns = [
    path('user/signup/', DefaultUserSignupView.as_view(), name='default_user_signup'),
    path('user/login/', DefaultUserLoginView.as_view(), name='default_user_login'),
    path('user/logout/', UserLogoutView.as_view(), name='default_user_logout'),
    path('user/my-tasks/', UserTaskListView.as_view(), name='my-tasks'),
    path('user/submit-screenshot/', SubmitTaskScreenshotView.as_view(), name='submit-screenshot'),
    path('user/dashboard/', UserDashboardView.as_view(), name='user-dashboard'),
    path('user/verify/', UserVerifyAPIView.as_view(), name='user-token-verify'),
]
