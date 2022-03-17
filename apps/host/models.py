from django.db import models
#from django.contrib.auth.models import User
from apps.user.models import User


# Create your models here.
from apps.sai.models import Sai


class Host(models.Model):
    """
      Modelo de datos de los Host
    """
    name_host = models.CharField(max_length=100, null=True, blank=True)
    ip = models.GenericIPAddressField(null=True)
    mac = models.CharField(max_length=100, null=True, default="")
    so = models.CharField(max_length=1, null=True)
    group = models.ForeignKey('group.Group', related_name='host', on_delete=models.CASCADE, null=True)
    order = models.CharField(max_length=50, null=True)
    description = models.TextField(null=True, blank=True)
    pool = models.ForeignKey('pool.Pool', related_name='host', on_delete=models.CASCADE, null=True)
    user = models.ForeignKey(User, related_name='host', on_delete=models.CASCADE)
    #user = models.ForeignKey('user.User', related_name='host', on_delete=models.CASCADE)
    type_host = models.CharField(max_length=20, null=True)
    sais = models.ManyToManyField('sai.Sai', related_name='sais_hosts', blank=True)  # <- Un HOST puede tener muchos SAIS y un SAI puede tener muchos HOSTS


    class Meta:
        db_table = 'HOST'

    def __str__(self):
        return '{}'.format(self.name_host)
