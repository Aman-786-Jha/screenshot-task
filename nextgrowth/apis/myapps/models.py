from django.db import models
from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from .model_manager import NextGrowthBaseUserManager
import uuid
import jwt
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from .choices import *

from datetime import date


# Create your models here.
class CommonTimePicker(models.Model):
    """
    An abstract model in Django that provides two fields, `created_at` and `updated_at`, which automatically record the date and time when an object is created or updated.
    """
    created_at = models.DateTimeField("Created Date", auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField("Updated Date", auto_now=True, db_index=True)
    class Meta:
        abstract = True




class NextGrowthBaseUser(AbstractBaseUser,CommonTimePicker):

    # user Types
    user_type = models.CharField("User Type", max_length=10, choices=USER_TYPE_CHOICES,default='User',db_index=True)
    # user details
    full_name = models.CharField("Name",max_length=255, blank=True, null=True,db_index=True)
    profile_picture = models.ImageField(upload_to='profiles/', null=True, blank=True)
    points = models.PositiveIntegerField(default=0)
    email = models.EmailField("Email Address", null=True, blank=True, unique=True,db_index=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False,unique=True,db_index=True)
    gender = models.CharField("Gender", max_length=1, blank=True,choices=USER_GENDER_CHOICES,null=True)
    age = models.CharField("Age",max_length=100, blank=True, null= True)
    dob = models.DateField(max_length=200, null=True, blank=True)
    address = models.CharField(max_length=200, null=True, blank=True)
    # model flags
    is_superuser = models.BooleanField("Super User", default=False)
    is_active = models.BooleanField("Active", default=True,db_index=True)
    is_staff = models.BooleanField("Staff",default=False)
    is_rejected=models.BooleanField("Rejected", default=False,db_index=True)
    is_aproved=models.BooleanField("Aproved", default=False,db_index=True)
    is_blocked = models.BooleanField("Blocked", default=False,db_index=True)
    email_verify = models.BooleanField("Email Verify", default=False)
    login_status = models.BooleanField("Login Status", default=False)
    otp_verify = models.BooleanField("opt Verified", default=False)
    # other fields
    otp = models.CharField('OTP', max_length=4, blank=True, null=True)
    # model manager
    objects = NextGrowthBaseUserManager()
    USERNAME_FIELD = 'email'

    def calculate_age(self):
        if self.dob:
            today = date.today()
            return today.year - self.dob.year - ((today.month, today.day) < (self.dob.month, self.dob.day))
        return None
    def __str__(self):
        return f"{self.id}_{self.user_type}_{self.email}_{self.uuid}" 
    
    def has_perm(self, perm, obj=None):
        return self.is_staff
    
    def has_module_perms(self, app_label):
        return self.is_superuser

    


    @property
    def is_staff(self):
        return self.is_superuser
   
    def save(self, *args, **kwargs):
        self.slug = slugify(f"{self.email}_{self.uuid}")
        super().save(*args, **kwargs)
    
    @staticmethod
    def decode_jwt(token):
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = payload['user_id']
            return NextGrowthBaseUser.objects.get(uuid=user_id)
        except (jwt.DecodeError, NextGrowthBaseUser.DoesNotExist):
            return None
        
    def save(self, *args, **kwargs):
        super(NextGrowthBaseUser, self).save(*args, **kwargs)
        
    class Meta:
        ordering = ['-id']



class AppTask(CommonTimePicker):
    title = models.CharField(max_length=100)
    description = models.TextField()
    image = models.ImageField(upload_to='apps/')
    download_link = models.URLField()
    points = models.PositiveIntegerField()

    def __str__(self):
        return f"{self.title}_{self.id}"
    

class TaskSubmission(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    )

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    task = models.ForeignKey(AppTask, on_delete=models.CASCADE)
    screenshot = models.ImageField(upload_to='screenshots/')
    user_submitted_at = models.DateTimeField(null=True, blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField("Created Date", default=timezone.now, db_index=True)
    updated_at = models.DateTimeField("Updated Date", auto_now=True, db_index=True)

    def __str__(self):
        return f"{self.user.full_name} - {self.task.title}"

