from rest_framework import serializers
from .models import *

class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRegistration
        fields = ['email','firstname','lastname','id','is_blocked','role']
   
class PrincipalSerializer(serializers.ModelSerializer):
    user = UserRegistrationSerializer()

    class Meta:
        model = Principal
        fields='__all__'
     

class SubjectSerializer(serializers.ModelSerializer):
    class Meta:
        model= Subject
        fields= '__all__'
        
        
class StudentSerializer(serializers.ModelSerializer):
    user = UserRegistrationSerializer()
    subjects = SubjectSerializer()
    principal = PrincipalSerializer()    
    # teacher = serializers.SerializerMethodField()

    class Meta:
        model=Student
        fields='__all__'
    
class StudentSerializerNew(serializers.ModelSerializer):
    user = UserRegistrationSerializer()
    subjects = SubjectSerializer()
    # principal = PrincipalSerializer()    

    class Meta:
        model=Student

        exclude=['principal']

       
class TeacherSerializer(serializers.ModelSerializer):
    user = UserRegistrationSerializer()
    
    subjects = SubjectSerializer()

    
    # subjects_taught = serializers.SerializerMethodField()
    # # students_count = serializers.SerializerMethodField()
    # # # students_details = StudentSerializer(many=True, read_only=True, source='students')
    # # students_details = serializers.SerializerMethodField()
    
    
    class Meta:
        model=Teacher
        fields='__all__'
        # exclude=['subjects',]
        # read_only_fields = ('principal',)  # Make the 'principal' field read-only

    # def get_students_count(self, obj):
    #     return obj.students.count()
    
    # def get_subjects_taught(self, obj):
    #     subject = obj.subjects
    #     serialized_subject = {
    #         'subject_id': subject.id,
    #         'subject_name': subject.name,
    #     }
    #     return serialized_subject
    
    # def get_students_details(self, obj):
    #     # Retrieve students and their details for this teacher
    #     students = obj.students.all()
    #     serialized_students = []
    #     for student in students:
    #         serialized_student = {
    #             'student_id': student.user.id,
    #             'student_email': student.user.email,
    #             'student_firstname': student.user.firstname,
    #             'student_lastname': student.user.lastname,
    #         }
    #         serialized_students.append(serialized_student)
    #     return serialized_students


