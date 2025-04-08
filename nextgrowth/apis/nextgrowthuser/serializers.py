from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from apis.myapps.models import *
from datetime import datetime
# from nextgrowth.schedulers.scheduler import *
from django.db.models import Q



class DefaultUserSignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)

    gender = serializers.ChoiceField(
        required=True,
        choices=USER_GENDER_CHOICES,
        error_messages={
            'required': 'Gender is required.',
            'invalid_choice': 'Invalid gender choice.',
        },
    )

    class Meta:
        model = NextGrowthBaseUser
        fields = ['id', 'email', 'full_name', 'password', 'confirm_password', 'gender']

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        password = validated_data.pop('password')

        user = NextGrowthBaseUser(
            user_type='User',
            email_verify=True,
            otp_verify=True,
            **validated_data
        )
        user.set_password(password)
        user.save()
        return user


class DefaultUserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)

    class Meta:
        fields = ['email', 'password']



class AppTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = AppTask
        fields = '__all__'
        ref_name = "UserAppTaskSerializer"

class TaskSubmissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = TaskSubmission
        fields = ['id', 'task', 'screenshot', 'status', 'submitted_at']

class SubmitScreenshotSerializer(serializers.Serializer):
    task_id = serializers.UUIDField()
    screenshot = serializers.ImageField()



class UserDashboardTaskSerializer(serializers.ModelSerializer):
    task_title = serializers.CharField(source='task.title', read_only=True)
    task_points = serializers.IntegerField(source='task.points', read_only=True)
    submitted_at = serializers.DateTimeField(source='user_submitted_at', read_only=True)

    class Meta:
        model = TaskSubmission
        fields = ['id', 'task_title', 'task_points', 'status', 'submitted_at']
