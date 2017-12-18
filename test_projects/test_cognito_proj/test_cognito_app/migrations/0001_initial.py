# -*- coding: utf-8 -*-
# Generated by Django 1.9.7 on 2017-12-17 23:21
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('rest_framework_signature', '__first__'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('user_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='rest_framework_signature.User')),
                ('new_field', models.CharField(blank=True, max_length=12, null=True)),
            ],
            bases=('rest_framework_signature.user',),
        ),
    ]
