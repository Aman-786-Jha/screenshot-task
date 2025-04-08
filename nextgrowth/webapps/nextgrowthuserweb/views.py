from django.views import View
from django.shortcuts import render

class UserSignupPageView(View):
    template_name = 'UsersidesPages/user_register.html'

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)


class UserLoginPageView(View):
    template_name = 'UsersidesPages/user_login.html'  
    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)
    


class UserDashboardPageView(View):
    template_name = 'UsersidesPages/user_dashboard.html'  

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



