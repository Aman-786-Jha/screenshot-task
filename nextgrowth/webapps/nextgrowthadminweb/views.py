from django.views import View
from django.shortcuts import render

class AdminSignupPageView(View):
    template_name = 'AdminPages/admin_signup.html'  

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)


class AdminLoginPageView(View):
    template_name = 'AdminPages/login.html'  

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)
    


class AdminDashboardPageView(View):
    # template_name = 'AdminPages/admin_dashboard.html'  
    template_name = 'AdminPages/list-task.html'  

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)

class AdminAddTaskPageView(View):
    template_name = 'AdminPages/add_task.html'  

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)
    

class AdminListTaskPageView(View):
    template_name = 'AdminPages/list-task.html'  

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)
    

class AdminEditTaskPageView(View):
    template_name = 'AdminPages/task-edit.html'

    def get(self, request, *args, **kwargs):
        task_id = kwargs.get('task_id')
        return render(request, self.template_name, {'task_id': task_id})
    


class AdminAssigntTaskPageView(View):
    template_name = 'AdminPages/assign-task.html'  

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)
    
class AdminAssignListTaskPageView(View):
    template_name = 'AdminPages/assigned-task-list.html'  

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)
    





# from django.shortcuts import render, redirect
# from django.views import View
# from django.contrib import messages

# class AdminDashboardPageView(View):
#     template_name = 'AdminPages/admin_dashboard.html'  

#     def get(self, request, *args, **kwargs):
#         if request.user.is_authenticated and request.user.user_type == "Admin":
#             return render(request, self.template_name)
#         else:
#             messages.error(request, "You are not authorized to access this page.")
#             return redirect('Admin:admin-login-page') 



