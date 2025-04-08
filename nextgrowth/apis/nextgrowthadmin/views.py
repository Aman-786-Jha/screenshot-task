from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny,IsAuthenticated, IsAdminUser
from django.contrib.auth import authenticate, login
from rest_framework_simplejwt.tokens import RefreshToken
from drf_yasg.utils import swagger_auto_schema
from apis.myapps.models import *
from .serializers import *
from drf_yasg import openapi
from django.contrib.auth import authenticate
from rest_framework.exceptions import NotFound
from django.http import JsonResponse
from django.views import View
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from apis.myapps.models import AppTask
from .serializers import AppTaskSerializer
from .helpers import is_admin_authenticated 
from django.shortcuts import get_object_or_404
from rest_framework.parsers import MultiPartParser, FormParser
from drf_yasg import openapi
from rest_framework_simplejwt.authentication import JWTAuthentication



AUTH_HEADER_PARAM = openapi.Parameter(
    name='Authorization',
    in_=openapi.IN_HEADER,
    type=openapi.TYPE_STRING,
    required=True,
    default='Bearer ',
    description='Bearer Token',
)


####################### Default Developer type user signup ###################

class NextGrowthBaseUserSignupView(APIView):
    permission_classes = [AllowAny]
    @swagger_auto_schema(
        request_body=NextGrowthBaseUserSingupSerializer,
    responses={
        201: openapi.Response(description='Created', schema=NextGrowthBaseUserSingupSerializer),
        400: openapi.Response(description='Bad Request', schema=openapi.Schema(type=openapi.TYPE_OBJECT)),
    }
)

    def post(self, request):
        try:
            serializer = NextGrowthBaseUserSingupSerializer(data=request.data)
            print('data----------->', request.data)
            if serializer.is_valid():
                # serializer.validated_data['is_superuser'] = True

                obj = serializer.save()

                return Response(
                    {
                        'responseCode': status.HTTP_201_CREATED,
                        'responseMessage': "Default developer type user created successfully!",
                        'responseData': {
                            "full_name": obj.full_name,
                            "email": obj.email,
                            "uuid": obj.uuid,
                        }
                    },
                    status=status.HTTP_201_CREATED
                )

            return Response(
                {
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'responseMessage': [f"{error[1][0]}" for error in dict(serializer.errors).items()][0],
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        except serializers.ValidationError as e:
            return Response(
                {
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'responseMessage': [f"{error[1][0]}" for error in dict(e).items()][0],
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            print("DeveloperSignupView Error -->", e)
            return Response(
                {
                    'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                    'responseMessage': "Something went wrong! Please try again.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class NextGrowthBaseUserLoginView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=NextGrowthBaseUserLoginSerializer,
        responses={
            200: openapi.Response(description='OK', schema=NextGrowthBaseUserLoginSerializer),
            400: openapi.Response(description='Bad Request', schema=openapi.Schema(type=openapi.TYPE_OBJECT)),
            401: openapi.Response(description='Unauthorized', schema=openapi.Schema(type=openapi.TYPE_OBJECT)),
        }
    )
    def post(self, request):
        try:
            serializer = NextGrowthBaseUserLoginSerializer(data=request.data)
            
            if serializer.is_valid():
                email = serializer.validated_data.get('email')
                password = serializer.validated_data.get('password')
                
                if NextGrowthBaseUser.objects.filter(email=email).exists():
                    user=NextGrowthBaseUser.objects.get(email=email)
                    
                    if user and user.otp_verify and user.check_password(password) and user.user_type == 'Admin':
                        refresh = RefreshToken.for_user(user)
                        access_token = str(refresh.access_token)
                        refresh_token = str(refresh)
                        user.is_active=True
                        user.login_status=True
                        user.save()
                        return Response(
                            {
                                'responseCode': status.HTTP_200_OK,
                                'responseMessage': "Login successful",
                                'responseData': {
                                    "full_name": user.full_name,
                                    "email": user.email,
                                    "uuid": user.uuid,
                                    'access_token': access_token,
                                    'refresh_token': refresh_token
                                }
                            },
                            status=status.HTTP_200_OK
                        )
                    elif user and not user.otp_verify:
                        return Response(
                            {
                                'responseCode': status.HTTP_400_BAD_REQUEST,
                                'responseMessage': "OTP not verified",
                            },
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    elif user.user_type != 'Admin':
                        return Response(
                            {
                                'responseCode': status.HTTP_400_BAD_REQUEST,
                                'responseMessage': "You are not allowed to perform this action.",
                            },
                            status=status.HTTP_400_BAD_REQUEST
                        )

                    return Response(
                        {
                            'responseCode': status.HTTP_401_UNAUTHORIZED,
                            'responseMessage': "Invalid credentials",
                        },
                        status=status.HTTP_401_UNAUTHORIZED
                    )

                return Response(
                        {
                            'responseCode': status.HTTP_401_UNAUTHORIZED,
                            'responseMessage': "User Is not Valid",
                        },
                        status=status.HTTP_401_UNAUTHORIZED
                    )

        except serializers.ValidationError as e:
            return Response(
                {
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'responseMessage': [f"{error[1][0]}" for error in dict(e).items()][0],
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            print("AdminLoginView Error -->", e)
            return Response(
                {
                    'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                    'responseMessage': "Something went wrong! Please try again.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
         
class UserLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                name='Authorization',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True,
                default='Bearer ',
                description='Bearer Token',
            ),
        ],
        responses={
            200: openapi.Response(description='OK'),
            401: openapi.Response(description='Unauthorized', schema=openapi.Schema(type=openapi.TYPE_OBJECT)),
        }
    )
    def post(self, request):
        try:
            user = request.user

            if not user.login_status:
                return Response(
                    {
                        'responseCode': status.HTTP_400_BAD_REQUEST,
                        'responseMessage': "User already logged out",
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )


            user.login_status = False
            user.is_active = False
            user.save()

            return Response(
                {
                    'responseCode': status.HTTP_200_OK,
                    'responseMessage': "Logout successful",
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            print("AdminLogoutView Error -->", e)
            return Response(
                {
                    'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                    'responseMessage': "Something went wrong! Please try again.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class AppTaskCreateView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    @swagger_auto_schema(
        manual_parameters=[
            AUTH_HEADER_PARAM,
            openapi.Parameter('title', openapi.IN_FORM, type=openapi.TYPE_STRING, required=True),
            openapi.Parameter('description', openapi.IN_FORM, type=openapi.TYPE_STRING, required=True),
            openapi.Parameter('download_link', openapi.IN_FORM, type=openapi.TYPE_STRING, required=True),
            openapi.Parameter('points', openapi.IN_FORM, type=openapi.TYPE_INTEGER, required=True),
            openapi.Parameter('image', openapi.IN_FORM, type=openapi.TYPE_FILE, required=True),
        ],
        responses={
            201: openapi.Response(description='Created'),
            400: openapi.Response(description='Bad Request'),
            401: openapi.Response(description='Unauthorized'),
        }
    )
    def post(self, request):
        try:
            is_valid, message = is_admin_authenticated(request)
            if not is_valid:
                return Response({
                    'responseCode': status.HTTP_401_UNAUTHORIZED,
                    'responseMessage': message,
                }, status=status.HTTP_401_UNAUTHORIZED)

            serializer = AppTaskSerializer(data=request.data)
            if serializer.is_valid():
                obj = serializer.save()
                return Response({
                    'responseCode': status.HTTP_201_CREATED,
                    'responseMessage': "Task created successfully!",
                    'responseData': AppTaskSerializer(obj).data,
                }, status=status.HTTP_201_CREATED)

            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'responseMessage': serializer.errors,
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            print("AppTaskCreateView Error -->", e)
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'responseMessage': "Something went wrong! Please try again.",
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class AppTaskListView(APIView):

    @swagger_auto_schema(
        manual_parameters=[AUTH_HEADER_PARAM],
        responses={
            200: openapi.Response(description='OK'),
            401: openapi.Response(description='Unauthorized'),
        }
    )
    def get(self, request):
        try:
            is_valid, message = is_admin_authenticated(request)
            print('is_valid---------------->', is_valid)
            print('message---------------->', message)
            if not is_valid:
                return Response({
                    'responseCode': status.HTTP_401_UNAUTHORIZED,
                    'responseMessage': message,
                }, status=status.HTTP_401_UNAUTHORIZED)

            tasks = AppTask.objects.all()
            serializer = AppTaskSerializer(tasks, many=True,context={'request': request})
            return Response({
                'responseCode': status.HTTP_200_OK,
                'responseMessage': "Tasks fetched successfully!",
                'responseData': serializer.data,
            }, status=status.HTTP_200_OK)
        except Exception as e:
            print("AppTaskListView Error -->", e)
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'responseMessage': "Something went wrong!",
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# class AppTaskUpdateView(APIView):

#     @swagger_auto_schema(
#         manual_parameters=[AUTH_HEADER_PARAM],
#         request_body=AppTaskSerializer,
#         responses={
#             200: openapi.Response(description='Updated'),
#             400: openapi.Response(description='Bad Request'),
#             401: openapi.Response(description='Unauthorized'),
#             404: openapi.Response(description='Not Found'),
#         }
#     )
#     def put(self, request, pk):
#         try:
#             is_valid, message = is_admin_authenticated(request)
#             if not is_valid:
#                 return Response({
#                     'responseCode': status.HTTP_401_UNAUTHORIZED,
#                     'responseMessage': message,
#                 }, status=status.HTTP_401_UNAUTHORIZED)

#             try:
#                 task = AppTask.objects.get(pk=pk)
#             except AppTask.DoesNotExist:
#                 return Response({
#                     'responseCode': status.HTTP_404_NOT_FOUND,
#                     'responseMessage': "Task not found",
#                 }, status=status.HTTP_404_NOT_FOUND)

#             serializer = AppTaskSerializer(task, data=request.data)
#             if serializer.is_valid():
#                 obj = serializer.save()
#                 return Response({
#                     'responseCode': status.HTTP_200_OK,
#                     'responseMessage': "Task updated successfully!",
#                     'responseData': AppTaskSerializer(obj).data,
#                 }, status=status.HTTP_200_OK)

#             return Response({
#                 'responseCode': status.HTTP_400_BAD_REQUEST,
#                 'responseMessage': serializer.errors,
#             }, status=status.HTTP_400_BAD_REQUEST)

#         except Exception as e:
#             print("AppTaskUpdateView Error -->", e)
#             return Response({
#                 'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
#                 'responseMessage': "Something went wrong!",
#             }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AppTaskUpdateView(APIView):
    parser_classes = [MultiPartParser, FormParser]

    @swagger_auto_schema(
        manual_parameters=[AUTH_HEADER_PARAM],
        request_body=AppTaskSerializer,
        consumes=["multipart/form-data"],
        operation_description="Update task with optional image field.",
        responses={
            200: openapi.Response(description='Updated'),
            400: openapi.Response(description='Bad Request'),
            401: openapi.Response(description='Unauthorized'),
            404: openapi.Response(description='Not Found'),
        }
    )
    def put(self, request, pk):
        try:
            is_valid, message = is_admin_authenticated(request)
            if not is_valid:
                return Response({
                    'responseCode': status.HTTP_401_UNAUTHORIZED,
                    'responseMessage': message,
                }, status=status.HTTP_401_UNAUTHORIZED)

            try:
                task = AppTask.objects.get(pk=pk)
            except AppTask.DoesNotExist:
                return Response({
                    'responseCode': status.HTTP_404_NOT_FOUND,
                    'responseMessage': "Task not found",
                }, status=status.HTTP_404_NOT_FOUND)

            serializer = AppTaskSerializer(task, data=request.data, partial=True)  
            if serializer.is_valid():
                obj = serializer.save()
                return Response({
                    'responseCode': status.HTTP_200_OK,
                    'responseMessage': "Task updated successfully!",
                    'responseData': AppTaskSerializer(obj).data,
                }, status=status.HTTP_200_OK)

            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'responseMessage': serializer.errors,
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            print("AppTaskUpdateView Error -->", e)
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'responseMessage': "Something went wrong!",
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        

    # def patch(self, request, pk):
    #     try:
    #         is_valid, message = is_admin_authenticated(request)
    #         if not is_valid:
    #             return Response({
    #                 'responseCode': status.HTTP_401_UNAUTHORIZED,
    #                 'responseMessage': message,
    #             }, status=status.HTTP_401_UNAUTHORIZED)

    #         try:
    #             task = AppTask.objects.get(pk=pk)
    #         except AppTask.DoesNotExist:
    #             return Response({
    #                 'responseCode': status.HTTP_404_NOT_FOUND,
    #                 'responseMessage': "Task not found",
    #             }, status=status.HTTP_404_NOT_FOUND)

    #         serializer = AppTaskSerializer(task, data=request.data)
    #         if serializer.is_valid():
    #             obj = serializer.save()
    #             return Response({
    #                 'responseCode': status.HTTP_200_OK,
    #                 'responseMessage': "Task updated successfully!",
    #                 'responseData': AppTaskSerializer(obj).data,
    #             }, status=status.HTTP_200_OK)

    #         return Response({
    #             'responseCode': status.HTTP_400_BAD_REQUEST,
    #             'responseMessage': serializer.errors,
    #         }, status=status.HTTP_400_BAD_REQUEST)

    #     except Exception as e:
    #         print("AppTaskUpdateView Error -->", e)
    #         return Response({
    #             'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
    #             'responseMessage': "Something went wrong!",
    #         }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AppTaskDeleteView(APIView):

    @swagger_auto_schema(
        manual_parameters=[AUTH_HEADER_PARAM],
        responses={
            204: openapi.Response(description='Deleted'),
            401: openapi.Response(description='Unauthorized'),
            404: openapi.Response(description='Not Found'),
        }
    )
    def delete(self, request, pk):
        try:
            is_valid, message = is_admin_authenticated(request)
            if not is_valid:
                return Response({
                    'responseCode': status.HTTP_401_UNAUTHORIZED,
                    'responseMessage': message,
                }, status=status.HTTP_401_UNAUTHORIZED)

            try:
                task = AppTask.objects.get(pk=pk)
                task.delete()
                return Response({
                    'responseCode': status.HTTP_204_NO_CONTENT,
                    'responseMessage': "Task deleted successfully!"
                }, status=status.HTTP_204_NO_CONTENT)

            except AppTask.DoesNotExist:
                return Response({
                    'responseCode': status.HTTP_404_NOT_FOUND,
                    'responseMessage': "Task not found",
                }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            print("AppTaskDeleteView Error -->", e)
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'responseMessage': "Something went wrong!",
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class AppTaskDetailView(APIView):

    @swagger_auto_schema(
        manual_parameters=[AUTH_HEADER_PARAM],
        responses={
            200: openapi.Response(description='OK'),
            401: openapi.Response(description='Unauthorized'),
            404: openapi.Response(description='Not Found'),
        }
    )
    def get(self, request, task_id):
        try:
            is_valid, message = is_admin_authenticated(request)
            if not is_valid:
                return Response({
                    'responseCode': status.HTTP_401_UNAUTHORIZED,
                    'responseMessage': message,
                }, status=status.HTTP_401_UNAUTHORIZED)

            task = get_object_or_404(AppTask, id=task_id)
            serializer = AppTaskSerializer(task,context={'request': request})
            return Response({
                'responseCode': status.HTTP_200_OK,
                'responseMessage': "Task fetched successfully!",
                'responseData': serializer.data,
            }, status=status.HTTP_200_OK)

        except Exception as e:
            print("AppTaskDetailView Error -->", e)
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'responseMessage': "Something went wrong!",
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AssignTaskToUserView(APIView):
    @swagger_auto_schema(
        manual_parameters=[AUTH_HEADER_PARAM],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['task_id', 'user_id'],
            properties={
                'task_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'user_id': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
        ),
        responses={
            200: 'Task assigned successfully',
            400: 'Bad Request',
            401: 'Unauthorized',
        }
    )
    def post(self, request):
        try:
            is_valid, message = is_admin_authenticated(request)
            if not is_valid:
                return Response({'responseCode': 401, 'responseMessage': message}, status=401)

            task_id = request.data.get('task_id')
            user_id = request.data.get('user_id')

            if TaskSubmission.objects.filter(task_id=task_id, user_id=user_id).exists():
                return Response({'responseCode': 400, 'responseMessage': 'Task already assigned to user'}, status=400)

            TaskSubmission.objects.create(task_id=task_id, user_id=user_id)
            return Response({'responseCode': 200, 'responseMessage': 'Task assigned successfully'}, status=200)

        except Exception as e:
            print("AssignTaskToUserView Error -->", e)
            return Response({'responseCode': 500, 'responseMessage': 'Internal server error'}, status=500)


class ReviewTaskSubmissionView(APIView):
    @swagger_auto_schema(
        manual_parameters=[AUTH_HEADER_PARAM],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['submission_id', 'status'],
            properties={
                'submission_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'status': openapi.Schema(type=openapi.TYPE_STRING, enum=['approved', 'rejected']),
            },
        ),
        responses={
            200: 'Status updated',
            400: 'Bad Request',
            401: 'Unauthorized'
        }
    )
    def post(self, request):
        try:
            is_valid, message = is_admin_authenticated(request)
            if not is_valid:
                return Response({'responseCode': 401, 'responseMessage': message}, status=401)

            sub_id = request.data.get('submission_id')
            status_update = request.data.get('status')

            try:
                submission = TaskSubmission.objects.get(id=sub_id)
            except TaskSubmission.DoesNotExist:
                return Response({'responseCode': 400, 'responseMessage': 'Submission not found'}, status=400)

            submission.status = status_update
            submission.save()

            if status_update == 'approved':
                submission.user.points += submission.task.points
                submission.user.save()

            return Response({'responseCode': 200, 'responseMessage': f'Submission {status_update} successfully'}, status=200)

        except Exception as e:
            print("ReviewTaskSubmissionView Error -->", e)
            return Response({'responseCode': 500, 'responseMessage': 'Internal server error'}, status=500)





class AdminVerifyAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.user_type == "Admin":
            return Response({"status": True, "full_name": user.full_name})
        return Response({"status": False, "message": "Not an admin"}, status=403)
    





class UserListView(APIView):
    @swagger_auto_schema(
        manual_parameters=[AUTH_HEADER_PARAM],
        responses={
            200: openapi.Response(description='List of Users'),
            401: openapi.Response(description='Unauthorized'),
        }
    )
    def get(self, request):
        try:
            is_valid, message = is_admin_authenticated(request)
            if not is_valid:
                return Response({
                    'responseCode': status.HTTP_401_UNAUTHORIZED,
                    'responseMessage': message,
                }, status=status.HTTP_401_UNAUTHORIZED)

            users = NextGrowthBaseUser.objects.filter(user_type='User')  
            user_list = [{
                'id': user.id,
                'full_name': user.full_name
            } for user in users]

            return Response({
                'responseCode': 200,
                'responseMessage': "Users fetched successfully",
                'responseData': user_list,
            }, status=status.HTTP_200_OK)

        except Exception as e:
            print("UserListView Error -->", e)
            return Response({
                'responseCode': 500,
                'responseMessage': "Something went wrong!",
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class AssignedTaskListView(APIView):
    @swagger_auto_schema(
        manual_parameters=[AUTH_HEADER_PARAM],
        responses={
            200: openapi.Response(description='List of Assigned Tasks'),
            401: openapi.Response(description='Unauthorized'),
        }
    )
    def get(self, request):
        try:
            is_valid, message = is_admin_authenticated(request)
            if not is_valid:
                return Response({
                    'responseCode': 401,
                    'responseMessage': message,
                }, status=401)

            submissions = TaskSubmission.objects.select_related('user', 'task').all()

            result = []
            for submission in submissions:
                result.append({
                    "id": submission.id,
                    "user_name": submission.user.full_name,
                    "task_title": submission.task.title,
                    "assigned_at": submission.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "user_submitted_at": submission.user_submitted_at.strftime("%Y-%m-%d %H:%M:%S") if submission.user_submitted_at else None,
                    "status": submission.status,
                    "screenshot_url": submission.screenshot.url if submission.screenshot else None,
                    "points": submission.task.points
                })

            return Response({
                "responseCode": 200,
                "responseMessage": "Assigned tasks fetched successfully",
                "responseData": result
            }, status=200)

        except Exception as e:
            print("AssignedTaskListView Error -->", e)
            return Response({
                "responseCode": 500,
                "responseMessage": "Something went wrong!",
            }, status=500)

