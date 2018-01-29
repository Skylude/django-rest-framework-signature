# -*- coding: utf-8 -*-
# Generated by Django 1.9.7 on 2018-01-28 23:38
from __future__ import unicode_literals

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import rest_framework_signature.models.relational


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ApiEndpoint',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('endpoint', models.CharField(max_length=150)),
            ],
        ),
        migrations.CreateModel(
            name='ApiKey',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=128)),
                ('access_key', models.CharField(default=rest_framework_signature.models.relational.generate_key, max_length=128)),
                ('secret_access_key', models.CharField(default=rest_framework_signature.models.relational.generate_key, max_length=128)),
                ('updated', models.DateTimeField(default=django.utils.timezone.now)),
                ('created', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.CreateModel(
            name='ApiPermission',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('methods', models.CharField(blank=True, max_length=32, null=True)),
                ('api_endpoint', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rest_framework_signature.ApiEndpoint')),
                ('api_key', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rest_framework_signature.ApiKey')),
            ],
        ),
        migrations.CreateModel(
            name='AuthToken',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('key', models.CharField(default=rest_framework_signature.models.relational.generate_key, max_length=80)),
                ('auth_type', models.CharField(blank=True, max_length=150, null=True)),
                ('updated', models.DateTimeField(default=django.utils.timezone.now)),
                ('created', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.CreateModel(
            name='CognitoUser',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('cognito_sub_id', models.CharField(max_length=36, unique=True, validators=[django.core.validators.MinLengthValidator(36)])),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('username', models.CharField(blank=True, max_length=80, null=True)),
                ('password', models.CharField(blank=True, max_length=128, null=True)),
                ('first_name', models.CharField(max_length=100)),
                ('last_name', models.CharField(max_length=100)),
                ('is_active', models.BooleanField(default=True)),
                ('created', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated', models.DateTimeField(default=django.utils.timezone.now)),
                ('salt', models.CharField(blank=True, max_length=50, null=True)),
                ('password_reset_token', models.CharField(blank=True, max_length=50, null=True)),
                ('password_reset_token_created', models.DateTimeField(blank=True, null=True)),
                ('password_reset_token_expires', models.DateTimeField(blank=True, null=True)),
                ('password_reset_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('failed_login_attempts', models.IntegerField(blank=True, default=0, null=True)),
                ('last_failed_login', models.DateTimeField(blank=True, null=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='users_created', to='rest_framework_signature.User')),
                ('updated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='users_updated', to='rest_framework_signature.User')),
            ],
        ),
        migrations.AddField(
            model_name='authtoken',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rest_framework_signature.User'),
        ),
    ]
