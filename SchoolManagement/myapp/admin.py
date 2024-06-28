from django.contrib import admin

# Register your models here.
from .models import *

admin.site.register(UserRegistration)
admin.site.register(Subject)
admin.site.register(Teacher)
admin.site.register(Student)
admin.site.register(Principal)