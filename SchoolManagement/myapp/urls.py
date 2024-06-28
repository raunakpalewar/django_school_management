from django.urls import path
from .import views

from django.urls import re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi


schema_view = get_schema_view(
   openapi.Info(
      title="School Management System",
      default_version='v1',
      description="Test description",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)


urlpatterns = [
       path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
       path('Principal_Registration/',views.Principal_Registration.as_view()),
       path('verifyOTP/',views.VerifyOTP.as_view()),
       path('Login/',views.Login.as_view()),
       path('change_password/',views.changePassword.as_view()),
       path('Forgot_password_request_otp',views.ForgotPassword.as_view()),
       path('set_new_password/',views.SetNewPassword.as_view()),
       path('Logout/',views.UserLogout.as_view()),
       path('Other_User_Registration/',views.Normal_Registration.as_view()),
       path('Subject_registration_for_teacher',views.SubjectRegistration_for_teacher.as_view()),
       path('Available_subjects_and_teacher/',views.AvailableSubjects.as_view()),
       path('SubjectTeacher_Subscription_by_student',views.SubjectTeacher_Subscription_by_student.as_view()),
       path("Get_perticular_student_Details",views.Student_details.as_view()),
       path("Block_Unblock_user/",views.BlockUser.as_view()),
      #  path("Unblock_user/",views.UnblockUser.as_view()),
       path('teacher_Details/',views.Teacher_details.as_view()),
       path('principal_Details/',views.PrincipalDetails.as_view()),
       path('Update_Principal_Details/',views.UpdatePrincipalDetails.as_view()),
       path("Update_Teacher_Details/",views.UpdateTeacherDetails.as_view()),
       path("Update_student_Details/",views.UpdateStudentDetails.as_view()),
       path("Principal_Get_Teacher_detail/",views.Principal_Get_Teacher_detail.as_view()),
       path("Principal_Get_Student_detail/",views.Principal_Get_Student_detail.as_view()),
       path("Teacher_Get_Student_detail/",views.Teacher_Get_Student_detail.as_view())
]