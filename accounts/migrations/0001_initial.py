# Generated by Django 3.2 on 2021-12-20 10:39

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='SocialAuthenticatedUsers',
            fields=[
                ('social_user_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('email', models.EmailField(max_length=254)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('user_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('first_name', models.CharField(blank=True, max_length=50, null=True)),
                ('last_name', models.CharField(blank=True, max_length=50, null=True)),
                ('active', models.BooleanField(default=False)),
                ('staff', models.BooleanField(default=False)),
                ('admin', models.BooleanField(default=False)),
                ('source_provider', models.CharField(choices=[('Django', 'Django'), ('Google', 'Google'), ('Facebook', 'Facebook')], default='Django', max_length=15)),
                ('google_ID', models.CharField(blank=True, max_length=100, null=True)),
                ('facebook_ID', models.CharField(blank=True, max_length=100, null=True)),
                ('socialUserReference', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='accounts.socialauthenticatedusers')),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
