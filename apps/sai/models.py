from django.db import models
from apps.user.models import User


# Create your models here.
class Sai(models.Model):
    """
      Modelo de datos de los SAI
    """
    name_sai = models.CharField(max_length=100)
    userConnection = models.CharField(max_length=100)
    authKey = models.CharField(max_length=128)
    privKey = models.CharField(max_length=128)
    ip = models.GenericIPAddressField(null=True)
    mac = models.CharField(max_length=100)
    url = models.URLField(null=True)
    protocol = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    code_oid = models.CharField(max_length=100)
    value_off = models.CharField(max_length=50)
    value_on = models.CharField(max_length=50)
    administrator = models.ForeignKey(User, related_name='sai', on_delete=models.CASCADE, null=True)

    class Meta:
        db_table = 'SAI'

    def __str__(self):
        return '{}'.format(self.name_sai)