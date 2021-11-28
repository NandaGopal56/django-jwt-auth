from django.db import models
import uuid
from django.contrib.auth.models import(
    AbstractBaseUser, BaseUserManager
)

class UserManager(BaseUserManager):
    def create_user(self, email, first_name, last_name, password=None, is_staff=False, is_admin=False, *args, **kwargs):
        if not first_name:
            raise ValueError("Users must have an first name")
        if not last_name:
            raise ValueError("Users must have an last name")
        if not email:
            raise ValueError("Users must have an email address")
        
        user = self.model(
            email=self.normalize_email(email)
        )
        user.first_name = first_name
        user.last_name = last_name
        user.set_password(password)
        user.staff = is_staff
        user.admin = is_admin
        user.active = kwargs.get('is_active', False)
        user.google_ID = kwargs.get('google_ID', None)
        user.facebook_ID = kwargs.get('facebook_ID', None)
        user.source_provider = kwargs.get('source_provider', 'Django')
        user.save(using=self._db)
        return user

    def create_staffuser(self, email, first_name, last_name, password):
        user = self.create_user(
            email,
            first_name,
            last_name,
            password=password,
            is_staff=True,
            is_active = True
        )
        return user

    def create_superuser(self, email, first_name, last_name, password):
        print('self-superuser', email, first_name, last_name, password)
        user = self.create_user(
            email,
            first_name,
            last_name,
            password=password,
            is_admin=True,
            is_staff=True,
            is_active = True
        )
        return user


class User(AbstractBaseUser):

    PROVIDER_CHOICES = (
        ("Django", "Django"),
        ("Google", "Google"),
        ("Facebook", "Facebook"),
    )

    user_id = models.UUIDField(primary_key = True, default = uuid.uuid4, editable = False)
    email = models.EmailField(max_length=254, unique=True)
    first_name = models.CharField(max_length=50, blank=True, null=True)
    last_name = models.CharField(max_length=50, blank=True, null=True)
    active = models.BooleanField(default=False)
    staff = models.BooleanField(default=False)
    admin = models.BooleanField(default=False)

    source_provider = models.CharField(max_length=15,
                  choices=PROVIDER_CHOICES,
                  default="Django")
    google_ID = models.CharField(max_length=100, null=True, blank=True)
    facebook_ID = models.CharField(max_length=100, null=True, blank=True)


    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    objects = UserManager()

    def __str__(self):
        return self.email

    def get_first_name(self):
        return self.first_name

    def get_last_name(self):
        return self.last_name

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.staff

    @property
    def is_admin(self):
        return self.admin

    @property
    def is_active(self):
        return self.active