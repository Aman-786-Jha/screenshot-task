from django.urls import path 
from .views import * 
from . import views 


urlpatterns = [
    path('admin/signup/',NextGrowthBaseUserSignupView.as_view(),name='signup'),
    path('admin/login/',NextGrowthBaseUserLoginView.as_view(),name='login'),
    path('admin/logout/',UserLogoutView.as_view(),name='logout'),
    path('admin/task/create/', AppTaskCreateView.as_view(), name='admin-task-create'),
    path('admin/task/list/', AppTaskListView.as_view(), name='admin-task-list'),
    path('admin/app-task/<int:task_id>/', AppTaskDetailView.as_view(), name='app-task-detail'),
    path('admin/task/update/<int:pk>/', AppTaskUpdateView.as_view(), name='admin-task-update'),
    path('admin/task/delete/<int:pk>/', AppTaskDeleteView.as_view(), name='admin-task-delete'),
    path('admin/assign-task/', AssignTaskToUserView.as_view(), name='assign-task'),
    path('admin/review-submission/', ReviewTaskSubmissionView.as_view(), name='review-submission'),
    path('admin/verify/', AdminVerifyAPIView.as_view(), name='token-verify'),
    path('admin/users/', UserListView.as_view(), name='admin-users'),
    path('admin/assigned-task-list/', AssignedTaskListView.as_view(), name='assigned-task-list'),


]
