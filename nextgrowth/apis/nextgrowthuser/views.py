
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny,IsAuthenticated
from django.contrib.auth import authenticate, login
from rest_framework_simplejwt.tokens import RefreshToken
from drf_yasg.utils import swagger_auto_schema
from apis.myapps.models import *
from .serializers import *
from drf_yasg import openapi
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import update_last_login
from django.shortcuts import get_object_or_404
from django.http import HttpResponse
import csv
from django.utils import timezone
from rest_framework.parsers import FileUploadParser, FormParser, MultiPartParser
from rest_framework import status, parsers
import csv
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from .serializers import *
from .helpers import is_user_authenticated
from django.db.models import Sum





class DefaultUserSignupView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=DefaultUserSignupSerializer,
        responses={
            201: openapi.Response(description='Created'),
            400: openapi.Response(description='Bad Request'),
        }
    )
    def post(self, request):
        serializer = DefaultUserSignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                'responseCode': status.HTTP_201_CREATED,
                'responseMessage': "User registered successfully!",
                'responseData': {
                    "full_name": user.full_name,
                    "email": user.email,
                    "uuid": user.uuid,
                }
            }, status=status.HTTP_201_CREATED)
        return Response({
            'responseCode': status.HTTP_400_BAD_REQUEST,
            'responseMessage': list(serializer.errors.values())[0][0],
        }, status=status.HTTP_400_BAD_REQUEST)



class DefaultUserLoginView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=DefaultUserLoginSerializer,
        responses={
            200: openapi.Response(description='Success'),
            400: openapi.Response(description='Bad Request'),
            401: openapi.Response(description='Unauthorized'),
        }
    )
    def post(self, request):
        serializer = DefaultUserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = authenticate(email=email, password=password)

            if user and user.user_type == 'User':
                refresh = RefreshToken.for_user(user)
                user.is_active=True
                user.login_status=True
                user.save()
                return Response({
                    'responseCode': status.HTTP_200_OK,
                    'responseMessage': "Login successful!",
                    'responseData': {
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                        'user_id': user.id,
                        'email': user.email,
                        'full_name': user.full_name,
                        'uuid': user.uuid
                    }
                }, status=status.HTTP_200_OK)
            return Response({
                'responseCode': status.HTTP_401_UNAUTHORIZED,
                'responseMessage': "Invalid credentials or not a default user.",
            }, status=status.HTTP_401_UNAUTHORIZED)
        return Response({
            'responseCode': status.HTTP_400_BAD_REQUEST,
            'responseMessage': list(serializer.errors.values())[0][0],
        }, status=status.HTTP_400_BAD_REQUEST)



# class DefaultUserLogoutView(APIView):
#     permission_classes = [IsAuthenticated]

#     def post(self, request):
#         try:
#             refresh_token = request.data.get('refresh')
#             token = RefreshToken(refresh_token)
#             token.blacklist()

#             return Response({
#                 'responseCode': status.HTTP_200_OK,
#                 'responseMessage': 'Logout successful!'
#             }, status=status.HTTP_200_OK)

#         except Exception as e:
#             return Response({
#                 'responseCode': status.HTTP_400_BAD_REQUEST,
#                 'responseMessage': 'Invalid refresh token or already logged out.',
#             }, status=status.HTTP_400_BAD_REQUEST)


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
            print("UserLogoutView Error -->", e)
            return Response(
                {
                    'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                    'responseMessage': "Something went wrong! Please try again.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

AUTH_HEADER_PARAM = openapi.Parameter(
    name='Authorization',
    in_=openapi.IN_HEADER,
    type=openapi.TYPE_STRING,
    required=True,
    default='Bearer ',
    description='JWT Token in format: Bearer <token>'
)


class UserTaskListView(APIView):
    @swagger_auto_schema(
        manual_parameters=[AUTH_HEADER_PARAM],
        responses={
            200: AppTaskSerializer(many=True),
            401: 'Unauthorized'
        }
    )
    def get(self, request):
        try:
            is_valid, message = is_user_authenticated(request)
            if not is_valid:
                return Response({'responseCode': 401, 'responseMessage': message}, status=401)

            submissions = TaskSubmission.objects.filter(user=request.user)
            tasks = [submission.task for submission in submissions]
            data = AppTaskSerializer(tasks, many=True).data
            return Response({'responseCode': 200, 'responseMessage': 'Tasks fetched successfully', 'responseData': data}, status=200)

        except Exception as e:
            print("UserTaskListView Error -->", e)
            return Response({'responseCode': 500, 'responseMessage': 'Internal server error'}, status=500)


class SubmitTaskScreenshotView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    @swagger_auto_schema(
        manual_parameters=[
            AUTH_HEADER_PARAM,
            openapi.Parameter('task_id', openapi.IN_FORM, type=openapi.TYPE_INTEGER, required=True),
            openapi.Parameter('screenshot', openapi.IN_FORM, type=openapi.TYPE_FILE, required=True),
        ],
        responses={
            200: 'Submission successful',
            400: 'Bad Request',
            401: 'Unauthorized'
        }
    )
    def post(self, request):
        try:
            is_valid, message = is_user_authenticated(request)
            if not is_valid:
                return Response({'responseCode': 401, 'responseMessage': message}, status=401)

            task_id = request.data.get('task_id')
            screenshot = request.FILES.get('screenshot')

            try:
                submission = TaskSubmission.objects.get(user=request.user, task_id=task_id)
            except TaskSubmission.DoesNotExist:
                return Response({'responseCode': 400, 'responseMessage': 'Task not assigned to this user'}, status=400)

            submission.screenshot = screenshot
            submission.status = 'pending'
            submission.user_submitted_at = timezone.now()
            submission.save()

            return Response({'responseCode': 200, 'responseMessage': 'Task submitted successfully'}, status=200)

        except Exception as e:
            print("SubmitTaskScreenshotView Error -->", e)
            return Response({'responseCode': 500, 'responseMessage': 'Internal server error'}, status=500)
        



class UserDashboardView(APIView):
    @swagger_auto_schema(
        manual_parameters=[AUTH_HEADER_PARAM],
        operation_summary="User dashboard showing submitted tasks and points earned",
        responses={
            200: openapi.Response(
                description="Dashboard data fetched",
                # examples={
                #     "application/json": {
                #         "responseCode": 200,
                #         "responseMessage": "Dashboard data fetched successfully",
                #         "data": {
                #             "user": "John Doe",
                #             "email": "john@example.com",
                #             "tasks": [
                #                 {
                #                     "id": "uuid",
                #                     "task_title": "Follow Instagram Page",
                #                     "task_points": 50,
                #                     "status": "approved",
                #                     "submitted_at": "2024-07-17T14:30:00Z"
                #                 }
                #             ],
                #             "total_points_earned": 150
                #         }
                #     }
                # }
            ),
            401: "Unauthorized"
        }
    )
    def get(self, request):
        try:
            is_valid, message = is_user_authenticated(request)
            if not is_valid:
                return Response({'responseCode': 401, 'responseMessage': message}, status=401)

            user = request.user

            submissions = TaskSubmission.objects.filter(
                user=user,
                screenshot__isnull=False
            ).order_by('-user_submitted_at')

            total_points = submissions.filter(status='approved').aggregate(
                total=Sum('task__points')
            )['total'] or 0

            serialized_data = UserDashboardTaskSerializer(submissions, many=True).data

            return Response({
                'responseCode': 200,
                'responseMessage': 'Dashboard data fetched successfully',
                'data': {
                    'user': user.full_name,
                    'email': user.email,
                    'tasks': serialized_data,
                    'total_points_earned': total_points
                }
            }, status=200)

        except Exception as e:
            print("UserDashboardView Error -->", e)
            return Response({'responseCode': 500, 'responseMessage': 'Internal server error'}, status=500)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

class UserVerifyAPIView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.user_type == "User":
            return Response({"status": True, "full_name": user.full_name})
        return Response({"status": False, "message": "Not an user"}, status=403)