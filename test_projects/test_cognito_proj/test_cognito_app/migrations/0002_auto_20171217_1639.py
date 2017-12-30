# -*- coding: utf-8 -*-
# Generated by Django 1.9.7 on 2017-12-17 23:39
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('test_cognito_app', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='new_field',
        ),
        migrations.AddField(
            model_name='user',
            name='cognito_id',
            field=models.CharField(blank=True, max_length=80, null=True),
        ),
    ]