from django.shortcuts import render
from rest_framework import serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializer import *
from .models import *
from django.contrib.auth.hashers import make_password,check_password
from django.contrib.auth import login,logout
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.permissions import AllowAny,IsAuthenticated,IsAuthenticatedOrReadOnly,IsAdminUser
from rest_framework_simplejwt.authentication import JWTAuthentication,JWTStatelessUserAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.conf import settings
from datetime import timedelta
from .pagination import CustomPageNumberPagination
from django.db.models import Q
import re
import random
import string
from django.core.mail import send_mail
from django.utils import timezone

def generate_otp():
    return str(random.randint(100000,999999))

def generate_password():
    res = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    print(res)
    return str(res)

def send_email_for_otp(email,otp):
    subject='OTP for user Registration'
    message=f' Your opt for the Registration is -- {otp}'
    print(otp)
    from_email=settings.EMAIL_HOST_USER
    recipient_list=[email]
    send_mail(subject,message,from_email,recipient_list)
    
def send_email(email,password):
    subject='Password '
    message=f' Your Password for the Login is -- {password} --- please change password after first time login'
    from_email=settings.EMAIL_HOST_USER
    recipient_list=[email]
    send_mail(subject,message,from_email,recipient_list)
    
def get_token_for_user(user):
    refresh=RefreshToken.for_user(user)
    
    return {
        "access":str(refresh.access_token),
        "refresh":str(refresh)
    }
    
class Principal_Registration(APIView):
    @swagger_auto_schema(
        operation_description="This if for Principal Registration",
        operation_summary="This is for Principal Registration",
        tags=['OAuth'],  
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email':openapi.Schema(type=openapi.TYPE_STRING),
                'firstname':openapi.Schema(type=openapi.TYPE_STRING),
                'lastname':openapi.Schema(type=openapi.TYPE_STRING),
            },
            requried=['email','firtname','lastname']
        ),
    )
    def post(self,request):
        try:
            data=request.data
            try:
                email=data.get('email')
                # role=data.get('role')
                firstname=data.get('firstname')
                lastname=data.get('lastname')
                
                
                email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                
                if not email or not re.match(email_regex,email):
                    return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Invalid email format"}, status=status.HTTP_400_BAD_REQUEST)
                

                otp=generate_otp()
                send_email_for_otp(email,otp)
                user=UserRegistration.objects.create(email=email,otp=otp,firstname=firstname,lastname=lastname)
                user.otp_created_at=timezone.now()
                user.role='principal'
                user.user_created_at=timezone.now()
                user.is_registered=True
                principal = Principal.objects.create(user=user)  # Create a Teacher object

                user.save()
                return Response({'message':'user registered successfully'},status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({"status":status.HTTP_400_BAD_REQUEST,'message':str(e)},status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,'message':'could not register user try again'},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class VerifyOTP(APIView):
    @swagger_auto_schema(
        operation_description='Verify you email',
        operation_summary='user has to verify his/her email using the otp sended within 3 minutes',
        tags=['OAuth'],        
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email':openapi.Schema(type=openapi.TYPE_STRING),
                'otp':openapi.Schema(type=openapi.TYPE_NUMBER)
            },
        ),
    )
    def post(self,request):
        data=request.data
        email=data.get('email')
        otp=data.get('otp')
        
        try:
            user=UserRegistration.objects.get(email=email,is_registered=True)
            time_difference=timezone.now()-user.otp_created_at
            if time_difference <= timedelta(minutes=3):
                if otp==user.otp:
                    user.is_verified=True
                    onetime_password=generate_password()
                    send_email(email,onetime_password)
                    user_password=make_password(onetime_password)

                    user.password=user_password
                    user.save()
                    return Response({'status':status.HTTP_200_OK, 'message':"User Verified Successfully"},status=status.HTTP_200_OK)
                return Response({'status':status.HTTP_400_BAD_REQUEST,"message": "Invalid OTP"},status.HTTP_400_BAD_REQUEST)
            else:
                otp=generate_otp()
                send_email_for_otp(email,otp)
                user.otp=otp
                user.otp_created_at=timezone.now()
                user.save()
                return Response({'status':status.HTTP_400_BAD_REQUEST,"message": "time out for  OTP \n new opt sended \n try again using new otp"},status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status':status.HTTP_404_NOT_FOUND,"message": "User not found"},status.HTTP_404_NOT_FOUND)

            
class Login(APIView):
    @swagger_auto_schema(
        operation_description="login here",
        operation_summary='login to you account',
        tags=['OAuth'],        
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email','password'],
            properties={
                'email':openapi.Schema(type=openapi.TYPE_STRING),
                'password':openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
    )
    def post(self,request):
        try:
            data=request.data
    
            email=data.get('email')
            password=data.get('password')
            
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not email or not re.match(email_regex, email):
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Invalid email format"}, status=status.HTTP_400_BAD_REQUEST)
            if not password:
                return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Password is required."}, status=status.HTTP_400_BAD_REQUEST)
            
            user=UserRegistration.objects.get(email=email,is_verified=True,is_registered=True)
            try:
                if check_password(password, user.password):
                    if user.times_logged_in == 0 and user.one_time_password_changed == False:
                        token = get_token_for_user(user)

                        return Response({
                            "status": status.HTTP_200_OK,
                            'message': 'Please change your password on first login.',
                            "Your user id": user.id,
                            "token":token,
                            'You are': user.role,
                            'ChangePasswordRequired': True
                        }, status=status.HTTP_200_OK)
                    else:
                        try:
                            if user.one_time_password_changed==True and user.is_blocked==False:
                                if user.is_blocked==True:
                                    return Response({"message": "User blocked, please contact higher authority"},status=status.HTTP_400_BAD_REQUEST)
                                login(request, user)
                                user.times_logged_in += 1  
                                user.save()  
                                token = get_token_for_user(user)
                                serializer = UserRegistrationSerializer(user)
                                return Response({
                                    "status": status.HTTP_200_OK,
                                    'message': 'Login successful',
                                    'token': token,
                                    "Your user id": user.id,
                                    'You are': user.role,
                                    'ChangePasswordRequired': False
                                }, status=status.HTTP_200_OK)
                            else:
                                return Response({"message": "User not verified or is blocked, please change your temperory password then try again"},status=status.HTTP_400_BAD_REQUEST)
                        except:
                            return Response({"message": "User not verified, please verify your email first using OTP"},status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({"status": status.HTTP_400_BAD_REQUEST, 'message': "Invalid credentials"},status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({"status": status.HTTP_400_BAD_REQUEST, 'message': 'User not found', 'error': str(e)},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": status.HTTP_500_INTERNAL_SERVER_ERROR, "message": str(e)},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class changePassword(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description='change your password using your old password and for first time logged in user has to also change their temperory password from here',
        operation_summary='Change your Password',
        tags=['OAuth'],
        manual_parameters=[
                    openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
                ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email':openapi.Schema(type=openapi.TYPE_STRING),
                'old_password':openapi.Schema(type=openapi.TYPE_STRING),
                'new_password':openapi.Schema(type=openapi.TYPE_STRING),
                'confirm_password':openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
    )
    def post(self,request):
        try:
            data=request.data
            auth_user=request.user
            email=data.get('email')
            old_password=data.get('old_password')
            password=data.get('new_password')
            cpassword=data.get('confirm_password')
            
            if not password:
                return Response({"message": "Please enter a new password"}, status=status.HTTP_400_BAD_REQUEST)
            if password != cpassword:
                return Response({"message": "New password and Confirm password must be the same."}, status=status.HTTP_400_BAD_REQUEST)
            
            password_regex = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$'
            if not re.match(password_regex, password):
                return Response({"message": "Invalid password format"}, status=status.HTTP_403_FORBIDDEN)
            
            try:
                user=UserRegistration.objects.get(email=email)
                if auth_user!=user:
                    return Response({"message":"Unauthorised access detected, user cannot change password of other users","status":status.HTTP_401_UNAUTHORIZED},status.HTTP_401_UNAUTHORIZED)
                if check_password(old_password,user.password):

                    # if old_password==user.password:
                        user.set_password(password)
                        if user.times_logged_in==0:
                            user.one_time_password_changed=True
                            user.times_logged_in+=1
                            user.save()
                        else:
                            pass
                        user.save()
                        return Response({'status':status.HTTP_200_OK, 'message':"Password Changed Successfully"},status=status.HTTP_200_OK)
                    # return Response({'status':status.HTTP_400_BAD_REQUEST,"message": "Invalid Credentials"},status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({'status':status.HTTP_400_BAD_REQUEST,"messasge":"password not matched"},status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({'status':status.HTTP_404_NOT_FOUND,"message": "User not found"},status.HTTP_404_NOT_FOUND)
        except:
            return Response({'status':status.HTTP_500_INTERNAL_SERVER_ERROR,"message": "User not found"},status.HTTP_500_INTERNAL_SERVER_ERROR)



class ForgotPassword(APIView):
    @swagger_auto_schema(
        operation_description="Forgot Password",
        operation_summary="Reset Your password using new otp",
        tags=['OAuth'],        
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email'],
            properties={
                'email':openapi.Schema(type=openapi.TYPE_STRING)
            },
        ),
    )
    
    def post(self,request):
        try:
            data=request.data
            email = data.get('email')
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not email:
                return Response({'message': 'Email id is required.'}, status=status.HTTP_400_BAD_REQUEST)
            if not re.match(email_regex, email):
                return Response({'message': 'Please enter a valid email address.'}, status=status.HTTP_400_BAD_REQUEST)
            try:
                user = UserRegistration.objects.get(email=email)
                if user.times_logged_in==0 and user.one_time_password_changed==False:
                    onetime_password=generate_password()
                    send_email(email,onetime_password)
                    # user_password=make_password(onetime_password)
                    # user.password=user_password 
                    user.set_password(onetime_password) 
                    user.save()
                    return Response({'message': 'please check you email for temporary password'}, status=status.HTTP_200_OK)        
                otp=generate_otp()
                send_email_for_otp(email,otp)
                user.otp=otp
                user.otp_created_at=timezone.now()
                
                user.save()
                return Response({'message': 'OTP sent successfully for password reset.'}, status=status.HTTP_200_OK)

            except UserRegistration.DoesNotExist:
                return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except UserRegistration.DoesNotExist:
            return Response({'message': 'User not found.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SetNewPassword(APIView):
    @swagger_auto_schema(
        operation_description='Set New Password',
        operation_summary='Please Enter you new password',
        tags=['OAuth'],

        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email':openapi.Schema(type=openapi.TYPE_STRING),
                'otp':openapi.Schema(type=openapi.TYPE_NUMBER),
                'new_password':openapi.Schema(type=openapi.TYPE_STRING),
                'confirm_password':openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
    )
    def post(self,request):
        try:
            data=request.data
            email=data.get('email')
            otp=data.get('otp')
            password=data.get('new_password')
            cpassword=data.get('confirm_password')
            
            if not password:
                return Response({"message": "Please enter a new password"}, status=status.HTTP_400_BAD_REQUEST)
            if password != cpassword:
                return Response({"message": "New password and Confirm password must be the same."}, status=status.HTTP_400_BAD_REQUEST)
            
            password_regex = r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$'
            if not re.match(password_regex, password):
                return Response({"message": "Invalid password format"}, status=status.HTTP_403_FORBIDDEN)
            
            try:
                user=UserRegistration.objects.get(email=email)
                if user.one_time_password_changed==False:
                    return Response({"status":status.HTTP_401_UNAUTHORIZED,"message":"Unauthorised Please first verify you temperory password"},status.HTTP_401_UNAUTHORIZED)
                time_difference=timezone.now()-user.otp_created_at
                if time_difference <= timedelta(minutes=3):
                    if otp==user.otp:
                        # user_password=set_pass(password)
                        # user.password=user_password
                        user.set_password(password)
                        user.save()
                        return Response({'status':status.HTTP_200_OK, 'message':"Password Changed Successfully"},status=status.HTTP_200_OK)
                    return Response({'status':status.HTTP_400_BAD_REQUEST,"message": "Invalid OTP"},status.HTTP_400_BAD_REQUEST)
                else:
                    otp=generate_otp()
                    send_email_for_otp(email,otp)
                    user.otp=otp
                    user.otp_created_at=timezone.now()
                    user.save()
                    return Response({'status':status.HTTP_400_BAD_REQUEST,"message": "time out for  OTP \n new opt sended \n try again using new otp"},status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'status':status.HTTP_404_NOT_FOUND,"message": "User not found"},status.HTTP_404_NOT_FOUND)
        except:
            return Response({'status':status.HTTP_500_INTERNAL_SERVER_ERROR,"message": "User not found"},status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserLogout(APIView):
    def get(self,request):
        logout(request)
        return Response({"status":status.HTTP_200_OK,'message':'logout successfully done'},status.HTTP_200_OK)



class Normal_Registration(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="This if for teacher and student Registration. Teacher can be registerd by Principal and Student can be registerd by Teacher",
        operation_summary="Teacher and student Registration",
        tags=['OAuth'],  
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email':openapi.Schema(type=openapi.TYPE_STRING),
                'firstname':openapi.Schema(type=openapi.TYPE_STRING),
                'lastname':openapi.Schema(type=openapi.TYPE_STRING),
            },
            requried=['email','firtname','lastname']
        ),
    )
    def post(self,request):
        try:
            
            data=request.data
            auth_user=request.user
            try:
                email=data.get('email')
                firstname=data.get('firstname')
                lastname=data.get('lastname')
                
                
                email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                
                if not email or not re.match(email_regex,email):
                    return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': "Invalid email format"}, status=status.HTTP_400_BAD_REQUEST)
                

                otp=generate_otp()
                send_email_for_otp(email,otp)
                user=UserRegistration.objects.create(email=email,otp=otp,firstname=firstname,lastname=lastname)
                user.otp_created_at=timezone.now()
                
                if auth_user.role=='principal':
                    user.role='teacher'
                    teacher = Teacher.objects.create(user=user)  # Create a Teacher object
                    print(auth_user)
                    principal_instance = Principal.objects.get(user=auth_user)  # Get the Principal instance
                    teacher.principal = principal_instance  # Assign the Principal instance to teacher.principal                    teacher.save()
                    teacher.save()
                elif auth_user.role=='teacher':
                    user.role='student'
                    student = Student.objects.create(user=user)  # Create a Student object
                    student.save()
                    
                else:
                    return Response({'message':"your are not authorised to register new user",'status':status.HTTP_401_UNAUTHORIZED},status.HTTP_401_UNAUTHORIZED)
                
                
                user.user_created_at=timezone.now()
                user.is_registered=True
                user.save()
                return Response({'message':'user registered successfully'},status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({"status":status.HTTP_400_BAD_REQUEST,'message':str(e)},status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response({"status":status.HTTP_500_INTERNAL_SERVER_ERROR,'message':'could not register user try again'},status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SubjectRegistration_for_teacher(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="Register a subject for teachers",
        operation_summary="Subject Registration",
        tags=['Teacher'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING),
            },
            required=['name']
        ),
        responses={
            201: 'Subject registered successfully',
            400: 'Bad Request - Invalid subject data',
            401: 'Unauthorized - Only teachers are allowed to register subjects',
            500: 'Internal Server Error',
        },
    )
    def post(self, request):
        try:
            if not request.user.role == 'teacher':
                return Response({'message': "Only teachers are allowed to register subjects", 'status': status.HTTP_401_UNAUTHORIZED}, status=status.HTTP_401_UNAUTHORIZED)

            serializer = SubjectSerializer(data=request.data)
            if serializer.is_valid():
                subject_name = serializer.validated_data['name']
                subject, created = Subject.objects.get_or_create(name__iexact=subject_name)

                teacher = Teacher.objects.get(user=request.user)
                teacher.subjects = subject
                teacher.save()
                
                return Response({'message': 'Subject registered successfully'}, status=status.HTTP_201_CREATED)
            else:
                return Response({'message': 'Invalid subject data', 'errors': serializer.errors, 'status': status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
class AvailableSubjects(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List available subjects and their teachers for student selection",
        operation_summary="Available Subjects",
        tags=['Student'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
        ],
        responses={
            200: 'Successful response',
            500: 'Internal Server Error',
        },
    )
    def get(self, request):
        try:
            user=request.user
            if user.role=='student':
                subjects = Subject.objects.all()
                subject_teacher_data = []

                for subject in subjects:
                    teachers = Teacher.objects.filter(subjects=subject)
                    teacher_data = []

                    for teacher in teachers:
                        teacher_data.append({
                            'teacher_id': teacher.id,
                            'teacher_email': teacher.user.email,
                        })

                    subject_teacher_data.append({
                        'subject_id': subject.id,
                        'subject_name': subject.name,
                        'teachers': teacher_data,
                    })

                return Response({'subjects': subject_teacher_data}, status=status.HTTP_200_OK)
            else:
                return Response({"message":"Your are not allowed to view this data","status":status.HTTP_401_UNAUTHORIZED},status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SubjectTeacher_Subscription_by_student(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Subscribe to a teacher based on subject name and teacher ID",
        operation_summary="Student Subscription",
        tags=['Student'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'subject_name': openapi.Schema(type=openapi.TYPE_STRING),
                # 'teacher_id': openapi.Schema(type=openapi.TYPE_INTEGER),
            },
            required=['subject_name']
        ),
        responses={
            201: 'Subscription successful',
            400: 'Bad Request - Invalid data',
            500: 'Internal Server Error',
        },
    )
    def post(self, request):
        try:
            user=request.user
            if user.role=='student':
                subject_name = request.data.get('subject_name')
                # teacher_id = request.data.get('teacher_id')

                subject = Subject.objects.get(name=subject_name)
                teacher = Teacher.objects.get(subjects=subject.id)

                existing_subscription = Student.objects.filter(user=request.user, subjects=subject.id).exists()
                if existing_subscription:
                    return Response({'message': 'You are already subscribed to this teacher for the selected subject', 'status': status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)

                student = Student.objects.get(user=request.user)
                student.subjects=subject
                student.save()

                return Response({'message': 'Subscription successful'}, status=status.HTTP_201_CREATED)
            else:
                return Response({"message":"Your are not student","status":status.HTTP_401_UNAUTHORIZED},status.HTTP_401_UNAUTHORIZED)
        except Subject.DoesNotExist:
            return Response({'message': 'Subject not found', 'status': status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
        except Teacher.DoesNotExist:
            return Response({'message': 'Teacher not found', 'status': status.HTTP_400_BAD_REQUEST}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class Student_details(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class=CustomPageNumberPagination
    
    @swagger_auto_schema(
        operation_description='View student details',
        operation_summary='View student details',
        tags=['Student'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
            openapi.Parameter('page', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='1', description='Provide page number'),
            openapi.Parameter('page_size', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='10', description='Provide how many records you want'),
            openapi.Parameter('search', openapi.IN_QUERY, type=openapi.TYPE_STRING, required=False, description='Search by shopkeeper email or shopkeeper name'),
        ],
        responses={
            200: "Details retrieved successfully",
            400: "Bad Request",
            500: "Internal Server Error",
            401: "Unauthorized Access"
        },
    )
    
   
    def get(self, request):
        try:
            auth_user = request.user
            if auth_user.role == 'student':
                student = Student.objects.get(user=auth_user)
                serializer = StudentSerializer(student)
                teachers = Teacher.objects.filter(subjects=student.subjects)
                teacher_serializer = TeacherSerializer(teachers, many=True)
                response={
                    "student_data":serializer.data,
                    "teacher_data" : teacher_serializer.data
                }
                return Response(response, status=status.HTTP_200_OK)
            else:
                return Response({"message": "Unauthorized access", "status": status.HTTP_401_UNAUTHORIZED}, status=status.HTTP_401_UNAUTHORIZED)
        except Student.DoesNotExist:
            return Response({"message": "Student not found", "status": status.HTTP_404_NOT_FOUND}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"message": str(e), "status": status.HTTP_500_INTERNAL_SERVER_ERROR}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class BlockUser(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="To block the user, principals can block both teachers & students, and teachers can block students.",
        operation_summary="Block user",
        tags=['Block'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
        ],
        request_body=openapi.Schema(type=openapi.TYPE_OBJECT,
                    properties={
                        'user_email': openapi.Schema(type=openapi.TYPE_STRING, description='Email address of the user to block')
                    },
                    required=['user_email']
        ),
        responses={
            200: 'User blocked successfully',
            400: 'Bad Request',
            401: 'Unauthorized access',
            404: 'User not found',
            500: 'Internal Server Error',
        },
    )

    def post(self, request):
        try:
            blocking_user = request.user
            if blocking_user.role == 'principal':
                target_user_roles = ['teacher', 'student']
            elif blocking_user.role == 'teacher':
                target_user_roles = ['student']
            else:
                return Response({"Message": "Unauthorized to block users"}, status=status.HTTP_401_UNAUTHORIZED)

            user_email = request.data.get('user_email')

            user_to_block = UserRegistration.objects.filter(email=user_email, role__in=target_user_roles).first()

            if user_to_block:
                if user_to_block.is_blocked==False:
                    user_to_block.is_blocked = True
                    user_to_block.save()
                    return Response({"Message": f"{user_to_block.role.capitalize()} blocked successfully"}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    user_to_block.is_blocked = False
                    user_to_block.save()

                return Response({"Message": f"{user_to_block.role.capitalize()} unblocked successfully"}, status=status.HTTP_200_OK)
            else:
                return Response({"Message": "User not found with the provided email and role"}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"Message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UnblockUser(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="To unblock the user, principals can unblock both teachers & students, and teachers can unblock students.",
        operation_summary="Unblock user",
        tags=['Block'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
        ],
        request_body=openapi.Schema(type=openapi.TYPE_OBJECT,
                    properties={
                        'user_email': openapi.Schema(type=openapi.TYPE_STRING, description='Email address of the user to unblock')
                    },
                    required=['user_email']
        ),
        responses={
            200: 'User unblocked successfully',
            400: 'Bad Request',
            401: 'Unauthorized access',
            404: 'User not found',
            500: 'Internal Server Error',
        },
    )

    def post(self, request):
        try:
            unblocking_user = request.user
            if unblocking_user.role == 'principal':
                target_user_roles = ['teacher', 'student']
            elif unblocking_user.role == 'teacher':
                target_user_roles = ['student']
            else:
                return Response({"Message": "Unauthorized to unblock users"}, status=status.HTTP_401_UNAUTHORIZED)

            user_email = request.data.get('user_email')

            user_to_unblock = UserRegistration.objects.filter(email=user_email, role__in=target_user_roles).first()

            if user_to_unblock:
                if not user_to_unblock.is_blocked:
                    return Response({"Message": f"{user_to_unblock.role.capitalize()} is not blocked"}, status=status.HTTP_400_BAD_REQUEST)

                user_to_unblock.is_blocked = False
                user_to_unblock.save()

                return Response({"Message": f"{user_to_unblock.role.capitalize()} unblocked successfully"}, status=status.HTTP_200_OK)
            else:
                return Response({"Message": "User not found with the provided email and role"}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"Message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class Teacher_details(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = CustomPageNumberPagination

    @swagger_auto_schema(
        operation_description='View teacher details',
        operation_summary='View teacher details',
        tags=['Teacher'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
            openapi.Parameter('page', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='1', description='Provide page number'),
            openapi.Parameter('page_size', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='10', description='Provide how many records you want'),
            openapi.Parameter('search', openapi.IN_QUERY, type=openapi.TYPE_STRING, description='Search by student name', required=False),
        ],
        responses={
            200: "Details retrieved successfully",
            400: "Bad Request",
            500: "Internal Server Error",
            401: "Unauthorized Access"
        },
    )
    def get(self, request):
        try:
            auth_user = request.user
            if auth_user.role == 'teacher':
                teacher = Teacher.objects.get(user=request.user)

                search_query = request.GET.get('search')

                # Get the students associated with the teacher
                students = teacher.subjects.students.all()

                # Filter students based on the search query (if provided)
                if search_query:
                    students = students.filter(Q(user__firstname__icontains=search_query) | Q(user__lastname__icontains=search_query))

                # Use the TeacherDetailsSerializer to serialize teacher details
                paginator = self.pagination_class()
                paginated_students = paginator.paginate_queryset(queryset=students, request=request)
                teacherserializer = TeacherSerializer(teacher)
                students_serializer = StudentSerializer(paginated_students, many=True)
                pagecount = paginator.page.paginator.num_pages
                paginated_response = paginator.get_paginated_response(students_serializer.data)
                
              
                serialized_response = {
                    'status': status.HTTP_200_OK,
                    'total_pages': pagecount,
                    'Response': {
                        'data_count': paginated_response.data['count'],
                        'next': paginated_response.data['next'],
                        'previous': paginated_response.data['previous'],
                        'results': {"Teacher_data":teacherserializer.data,
                                    'students_details': StudentSerializer(students, many=True).data},
                        
                    },
                }

                return Response({"Response": serialized_response}, status.HTTP_200_OK)
            else:
                return Response({"Message": "Unauthorized access", "status": status.HTTP_401_UNAUTHORIZED}, status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"Message": str(e)}, status.HTTP_500_INTERNAL_SERVER_ERROR)


class PrincipalDetails(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = CustomPageNumberPagination

    @swagger_auto_schema(
        operation_description='View principal details',
        operation_summary='View principal details',
        tags=['Principal'],
        manual_parameters=[
            openapi.Parameter('Authorization', openapi.IN_HEADER, type=openapi.TYPE_STRING),
            openapi.Parameter('page', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='1', description='Provide page number'),
            openapi.Parameter('page_size', openapi.IN_QUERY, type=openapi.TYPE_STRING, default='10', description='Provide how many records you want'),
            openapi.Parameter('search', openapi.IN_QUERY, type=openapi.TYPE_STRING, required=False, description='Search by user email or full name'),

        ],
        responses={
            200: "Details retrieved successfully",
            400: "Bad Request",
            500: "Internal Server Error",
            401: "Unauthorized Access"
        },
    )
    def get(self, request):
        try:
            auth_user = request.user
            if auth_user.role == 'principal':
                try:
                    search_query = request.GET.get('search')
                    print(search_query)
                    print(auth_user.id)
                    principal = Principal.objects.get(user=auth_user)  
                    teachers = Teacher.objects.filter(principal=principal)
                    students = Student.objects.filter(principal=principal)

                    if search_query:
                        teachers = teachers.filter(
                            Q(user__email__icontains=search_query) | Q(user__firstname__icontains=search_query) | Q(user__lastname__icontains=search_query)
                        )
                        students = students.filter(
                            Q(user__email__icontains=search_query) | Q(user__firstname__icontains=search_query) | Q(user__lastname__icontains=search_query)
                        )

                    paginator = self.pagination_class()
                    teachers_page = paginator.paginate_queryset(teachers, request)
                    students_page = paginator.paginate_queryset(students, request)

                    teacher_serializer = TeacherSerializer(teachers_page, many=True)
                    student_serializer = StudentSerializer(students_page, many=True)
                    principal_serializer = PrincipalSerializer([principal], many=True)  # Serialize the principal as a list

                    response_data = {
                        "principal": principal_serializer.data[0],  # Extract the serialized principal from the list
                        "teachers": teacher_serializer.data,
                        "students": student_serializer.data,
                    }

                    serialized_response = {
                        'status': status.HTTP_200_OK,
                        'total_pages': paginator.page.paginator.num_pages,
                        'count': paginator.page.paginator.count,
                        'next': paginator.get_next_link(),
                        'previous': paginator.get_previous_link(),
                        'Response': response_data,
                    }

                    return Response({"Response": serialized_response}, status.HTTP_200_OK)
                except Exception as e:
                    return Response({"Response": status.HTTP_400_BAD_REQUEST, 'message': f"Could not fetch data Bad Request {str(e)}"}, status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"Message": "Unauthorized access", "status": status.HTTP_401_UNAUTHORIZED}, status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"Message": str(e)}, status.HTTP_500_INTERNAL_SERVER_ERROR)

        
class UpdatePrincipalDetails(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Update Principal Details only principal can update their information",
        operation_summary="Update Principal Details",
        tags=['Principal'],
        manual_parameters=[
            openapi.Parameter('Authorization',openapi.IN_HEADER,type=openapi.TYPE_STRING,required=True),            
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "firstname":openapi.Schema(type=openapi.TYPE_STRING,description="firstname"),
                "lastname":openapi.Schema(type=openapi.TYPE_STRING,description="lastname"),
                "password":openapi.Schema(type=openapi.TYPE_STRING,description="password"),
            }
        ),
            
        
        responses={
            200 : "Data updated Successfully",
            400 : "Bad Request",
            401 : "Unauthorised Access",
            501 : " Internal Server Error"
        },
    )
    def put(self,request):
        try:
            auth_user=request.user
            if auth_user.role=='principal':
                data=request.data
                principal_instance=UserRegistration.objects.get(email=auth_user.email)
                serializer=UserRegistrationSerializer(principal_instance,data,partial=True)  
                if serializer.is_valid():
                    if 'password' in data and data['password']:
                        auth_user.set_password(data['password'])
                        auth_user.save()
                    serializer.save()
                    serializer.save()  
                    return Response({"message":"data updated successfully","stauts":200},status.HTTP_200_OK)
                else:
                    return Response({"message": "Invalid data", "status": 400, "errors": serializer.errors},
                                    status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"status":400},status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"response ":"Internal Server error","status":f'{str(e)}'},status.HTTP_500_INTERNAL_SERVER_ERROR)


class UpdateTeacherDetails(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Update Teacher Details only principal can update their information",
        operation_summary="Update Teacher Details",
        tags=['Teacher'],
        manual_parameters=[
            openapi.Parameter('Authorization',openapi.IN_HEADER,type=openapi.TYPE_STRING,required=True),            
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "firstname":openapi.Schema(type=openapi.TYPE_STRING,description="firstname"),
                "lastname":openapi.Schema(type=openapi.TYPE_STRING,description="lastname"),
                "password":openapi.Schema(type=openapi.TYPE_STRING,description="password"),
                "subject" :openapi.Schema(type=openapi.TYPE_STRING,description="subject"),
            }
        ),
            
        
        responses={
            200 : "Data updated Successfully",
            400 : "Bad Request",
            401 : "Unauthorised Access",
            501 : " Internal Server Error"
        },
    )
    def put(self, request):
        try:
            auth_user = request.user
            if auth_user.role == 'teacher':
                data = request.data
                user_instance = UserRegistration.objects.get(email=auth_user.email)
                serializer = UserRegistrationSerializer(user_instance, data, partial=True)  
                if serializer.is_valid():
                    if 'password' in data and data['password']:
                        auth_user.set_password(data['password'])
                        auth_user.save()    
                    if 'subject' in data:
                        subject_name = data['subject']
                        try:
                            subject_instance, created = Subject.objects.get_or_create(name=subject_name)
                            teacher_instance=Teacher.objects.get(user=auth_user)
                            teacher_instance.subjects = subject_instance
                            teacher_instance.save()
                        except Subject.DoesNotExist:
                            return Response({"message": "Invalid subject", "status": 400}, status=status.HTTP_400_BAD_REQUEST)
                    serializer.save()
                    return Response({"message": "Data updated successfully", "status": 200}, status=status.HTTP_200_OK)
                else:
                    return Response({"message": "Invalid data", "status": 400, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"message": "Unauthorized Access", "status": 401}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"response": "Internal Server error", "status": f'{str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)    

class UpdateStudentDetails(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Update Teacher Details only principal can update their information",
        operation_summary="Update Teacher Details",
        tags=['Student'],
        manual_parameters=[
            openapi.Parameter('Authorization',openapi.IN_HEADER,type=openapi.TYPE_STRING,required=True),            
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "firstname":openapi.Schema(type=openapi.TYPE_STRING,description="firstname"),
                "lastname":openapi.Schema(type=openapi.TYPE_STRING,description="lastname"),
                "password":openapi.Schema(type=openapi.TYPE_STRING,description="password"),
                "subject" :openapi.Schema(type=openapi.TYPE_STRING,description="subject"),
            }
        ),
            
        
        responses={
            200 : "Data updated Successfully",
            400 : "Bad Request",
            401 : "Unauthorised Access",
            501 : " Internal Server Error"
        },
    )
    def put(self, request):
        try:
            auth_user = request.user
            if auth_user.role == 'student':
                data = request.data
                # user_instance = UserRegistration.objects.get(email=auth_user.email)
                # serializer = UserRegistrationSerializer(user_instance, data, partial=True)  
                
                student_instance = Student.objects.get(user=auth_user)
                serializer = UserRegistrationSerializer(student_instance.user, data, partial=True)

                
                if serializer.is_valid():
                    if 'password' in data and data['password']:
                        auth_user.set_password(data['password'])
                        auth_user.save()    
                    if 'subject' in data:
                        subject_name = data['subject']
                        try:
                            subject_instance, created = Subject.objects.get_or_create(name=subject_name)
                            teacher_instance=Teacher.objects.get(subjects=subject_instance)
                            student_instance.subjects = subject_instance
                            student_instance.save()
                        except Subject.DoesNotExist:
                            return Response({"message": "Invalid subject", "status": 400}, status=status.HTTP_400_BAD_REQUEST)
                    serializer.save()
                    return Response({"message": "Data updated successfully", "status": 200}, status=status.HTTP_200_OK)
                else:
                    return Response({"message": "Invalid data", "status": 400, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"message": "Unauthorized Access", "status": 401}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"response": "Internal Server error", "status": f'{str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)    
        
class Principal_Get_Teacher_detail(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    pagination_class=CustomPageNumberPagination
    
    @swagger_auto_schema(
        operation_description="Get all the teacher details working under you",
        operation_summary='Get teacher detail',
        tags=['Principal'],
        manual_parameters=[
            openapi.Parameter("Authorization",openapi.IN_HEADER,type=openapi.TYPE_STRING,required=True),
            openapi.Parameter("page",openapi.IN_QUERY,type=openapi.TYPE_STRING,default="1"),
            openapi.Parameter('search',openapi.IN_QUERY,type=openapi.TYPE_STRING,default="10"),
        ],
        responses={
            200 : "Details Retrived Successfully",
            400 : " BAd Request",
            401 : "Unauthorized Access",
            500 : "Internal Server Error"
        },
    )
    def get(self,request):
        try:
            auth_user=request.user
            if auth_user.role=='principal':
                try:
                    principal_instance=Principal.objects.get(user=auth_user.id)
                    teachers = Teacher.objects.filter(principal=principal_instance.id)
                    serializer = TeacherSerializer(teachers,many=True)
                    return Response({"Response":serializer.data,"status":status.HTTP_200_OK},status.HTTP_200_OK)  
                except Exception as e:
                    return Response({"Response":str(e),"status":status.HTTP_400_BAD_REQUEST},status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"Response":"unauthorised access","status":401},status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"Response":f"Internal Server Error - {str(e)}","status":500},status.HTTP_500_INTERNAL_SERVER_ERROR)

class Principal_Get_Student_detail(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    @swagger_auto_schema(
        operation_description='get all the student related to the principal',
        operation_summary='get all the students details',
        tags=['Principal'],
        manual_parameters=[
            openapi.Parameter("Authorization",openapi.IN_HEADER,type=openapi.TYPE_STRING),
            openapi.Parameter("page",openapi.IN_QUERY ,type=openapi.TYPE_STRING,default="1"),
            openapi.Parameter("page_size",openapi.IN_QUERY,type=openapi.TYPE_STRING,default="10"),
        ],
        responses={
            200 : "Data Retrived Successfully",
            400 : "Bad Request",
            500 : "Internal Server Error",
            401 : "Unauthorised Access",
        },
    )
    def get(self,request):
        try:
            auth_user=request.user
            if auth_user.role=='principal':
                principal_instance=Principal.objects.get(user=auth_user.id)
                students=Student.objects.filter(principal=principal_instance)
                serializer=StudentSerializerNew(students,many=True)
                return Response({"Response":serializer.data,"status":200},status.HTTP_200_OK)
            else:
                return Response({"Response":"error","status":401},status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"Response":"Bad Request","status":400},status.HTTP_400_BAD_REQUEST)

class Teacher_Get_Student_detail(APIView):
    authentication_classes=[JWTAuthentication]
    permission_classes=[IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="get all the student details for teacher",
        operation_summary='get all students',
        tags=['Teacher'],
        manual_parameters=[
            openapi.Parameter("Authorization",openapi.IN_HEADER,type=openapi.TYPE_STRING),
            openapi.Parameter('page',openapi.IN_QUERY,type=openapi.TYPE_STRING,default="1"),
            openapi.Parameter("page_size",openapi.IN_QUERY,type=openapi.TYPE_STRING,default="10"),
        ],
        responses={
            200:"Data Retrived Successfully",
            400 : "Bad Request",
            500 : "Internal Server Error",
            401 : " unauthorised error",
        },
    )
    def get(self,request):
        try:
            auth_user=request.user
            if auth_user.role=='teacher':
                teacher_instance=Teacher.objects.get(user=auth_user.id)
                print(teacher_instance)
                principal_instance=teacher_instance.principal.id
                students = Student.objects.filter(principal=principal_instance)

                serializer=StudentSerializerNew(students,many=True)
                return Response({"Response":serializer.data,"status":200},status.HTTP_200_OK)
            else:
                return Response({"Response":"Unauthorised access","status":401},status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"Response":f"Internal Server Error {str(e)}","status":500},status.HTTP_500_INTERNAL_SERVER_ERROR)