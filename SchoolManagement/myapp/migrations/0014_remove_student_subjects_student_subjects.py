# Generated by Django 4.2.6 on 2023-10-09 14:11

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0013_remove_teacher_principal_principal_students_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='student',
            name='subjects',
        ),
        migrations.AddField(
            model_name='student',
            name='subjects',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='students', to='myapp.subject'),
        ),
    ]
