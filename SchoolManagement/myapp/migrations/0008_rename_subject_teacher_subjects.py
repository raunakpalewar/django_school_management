# Generated by Django 4.2.6 on 2023-10-09 05:39

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0007_remove_teacher_subjects_teacher_subject_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='teacher',
            old_name='subject',
            new_name='subjects',
        ),
    ]
