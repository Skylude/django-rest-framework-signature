# -*- coding: utf-8 -*-
# Generated by Django 1.9.7 on 2018-01-28 23:39
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('rest_framework_signature', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('cognitouser_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='rest_framework_signature.CognitoUser')),
            ],
            bases=('rest_framework_signature.cognitouser',),
        ),
    ]
