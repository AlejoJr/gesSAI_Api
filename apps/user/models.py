from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):

    class Meta:
        db_table = 'USER'
        verbose_name = 'usuario'
        verbose_name_plural = verbose_name

    def __str__(self):
        return '{}'.format(self.username)

# Create your models here.
"""class User(AbstractBaseUser):
   
    name = models.CharField(max_length=100, null=True)
    login = models.CharField(max_length=50, null=True)
    email = models.CharField(max_length=100, null=True)
    type = models.CharField(max_length=1, null=False)
    nip = models.CharField(max_length=50, null=False)

    USERNAME_FIELD = 'username'

    class Meta:
        db_table = 'USER'
        #db_table = 'user_view'


    def __str__(self):
        return '{}'.format(self.name)
"""