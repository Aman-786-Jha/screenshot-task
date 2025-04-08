from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from apis.myapps.models import *
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from apis.myapps.choices import * 



class NextGrowthBaseUserSingupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)
    is_active = serializers.CharField(read_only=True)
    user_type = serializers.ChoiceField(
        read_only=True,
        choices=USER_TYPE_CHOICES,
        default='Dev', 
        error_messages={
            'required': 'User_Type is required.',
            'invalid_choice': 'Invalid User_Type choice.',
        },
    )
    gender = serializers.ChoiceField(
        required = True,
        choices=USER_GENDER_CHOICES,
        error_messages={
            'required': 'Gender is required.',
            'invalid_choice': 'Invalid gender choice.',
        },
    )
    class Meta:
        model = NextGrowthBaseUser
        fields = ['id', 'email', 'full_name', 'is_active', 'is_staff', 'password', 'confirm_password','user_type','gender']

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        password = validated_data.pop('password')

        user = NextGrowthBaseUser(user_type='Dev',**validated_data)
        user.email_verify= True
        user.otp_verify=True
        user.set_password(password)
        user.save()

        return user
    

class NextGrowthBaseUserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(
        write_only=True,
        required=True,
        error_messages={
            'required': 'Email is required.',
            'invalid': 'Enter a valid email address.',
        }
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        error_messages={
            'required': 'password is required.',
            'blank': 'Enter a valid password.',
        }
    )
    
    class Meta:
        fields = ['email', 'password'] 





class AppTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = AppTask
        fields = '__all__'
        ref_name = "AdminAppTaskSerializer"
        extra_kwargs = {
            'image': {'required': False, 'allow_null': True}
        }



class AssignTaskSerializer(serializers.Serializer):
    user_id = serializers.UUIDField()
    task_id = serializers.UUIDField()

class ReviewSubmissionSerializer(serializers.Serializer):
    submission_id = serializers.UUIDField()
    status = serializers.ChoiceField(choices=['approved', 'rejected'])
