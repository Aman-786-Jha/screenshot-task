from django.urls import path
from .views import AdminSignupPageView,AdminLoginPageView
from .views import *

urlpatterns = [
    path('admin/signup-page/', AdminSignupPageView.as_view(), name='admin-signup-page'),
    path('admin/login-page/', AdminLoginPageView.as_view(), name='admin-login-page'),
    path('admin/dashboard/', AdminDashboardPageView.as_view(), name='admin-login-dashboard'),
    path('admin/add-task/', AdminAddTaskPageView.as_view(), name='admin-add-task'),
    path('admin/list-task/', AdminListTaskPageView.as_view(), name='admin-list'),
    path('admin/assign-task/', AdminAssigntTaskPageView.as_view(), name='admin-assign-task'),
    path('admin/assign-task-list/', AdminAssignListTaskPageView.as_view(), name='admin-assign-list-task'),
    path('admin/edit-task/<int:task_id>/', AdminEditTaskPageView.as_view(), name='edit-task'),
    
]
