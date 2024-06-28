from django.db import models
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin

class CustomUserManager(BaseUserManager):
    def _create_user(self,email,password,**extra_fields):
        if not email:
            return ValueError("Please Provide Proper Email Address")
        
        email=self.normalize_email(email)
        user=self.model(email=email,**extra_fields)
        user.set_password(password)
        user.save(using=self.db)
        return user
    
    def create_user(self,email=None,password=None,**extra_fields):
        extra_fields.setdefault('is_staff',False)
        extra_fields.setdefault('is_superuser',False)
        return self._create_user(email,password,**extra_fields)
    
    def create_superuser(self,email=None,password=None,**extra_fields):
        extra_fields.setdefault('is_staff',True)
        extra_fields.setdefault('is_superuser',True)
        return self._create_user(email,password,**extra_fields)
    
class UserRegistration(AbstractBaseUser,PermissionsMixin):
    USER_ROLES=(
        ('principal','Principal'),
        ('teacher','Teacher'),
        ('student','student'),
    )
    
    email=models.EmailField(unique=True)
    firstname=models.CharField(max_length=255)
    lastname=models.CharField(max_length=255)
    password=models.CharField(max_length=255,null=True,blank=True)
    role=models.CharField(max_length=255,choices=USER_ROLES,null=True,blank=True)
    otp=models.IntegerField(null=True,blank=True)
    otp_created_at=models.DateTimeField(auto_now_add=True,blank=True,null=True)
    user_created_at=models.DateTimeField(auto_now_add=True,null=True,blank=True)
    is_staff=models.BooleanField(default=False)
    is_active=models.BooleanField(default=True)
    is_verified=models.BooleanField(default=False)
    is_registered=models.BooleanField(default=False)
    is_blocked=models.BooleanField(default=False)
    is_superuser=models.BooleanField(default=False)
    times_logged_in=models.IntegerField(null=True,blank=True,default=0)
    one_time_password_changed=models.BooleanField(default=False)
    
    objects=CustomUserManager()
    
    USERNAME_FIELD='email'
    REQUIRED_FIELDS=[]
    
    def __str__(self):
        return f'{self.email} -- {self.role}'
    

class Principal(models.Model):
    user = models.OneToOneField(UserRegistration, on_delete=models.CASCADE, related_name='principal', editable=False)
    def __str__(self):
        return f'{self.user} - {self.user.firstname} - {self.user.lastname}'


class Subject(models.Model):
    name = models.CharField(max_length=255)

    def save(self, *args, **kwargs):
        self.name = self.name.lower()
        super(Subject, self).save(*args, **kwargs)

    def __str__(self):
        return self.name
    
class Teacher(models.Model):
    user = models.OneToOneField(UserRegistration, on_delete=models.CASCADE, related_name='teacher', editable=False)
    subjects = models.OneToOneField(Subject, on_delete=models.CASCADE,null=True,blank=True ,related_name='teachers')
    principal=models.ForeignKey(Principal,on_delete=models.CASCADE,related_name='teacher_principal',null=True,blank=True)
    
    def __str__(self):
        return f'Teacher: {self.user.email} - {self.subjects}'


class Student(models.Model):
    user = models.OneToOneField(UserRegistration, on_delete=models.CASCADE, related_name='student', editable=False)
    subjects = models.ForeignKey(Subject,on_delete=models.SET_NULL, null=True, blank=True ,related_name='students')
    principal=models.ForeignKey(Principal,on_delete=models.CASCADE,related_name='student_pricipal',null=True,blank=True)

    def __str__(self):
        return f'Student: {self.user.email} - {self.subjects}'


