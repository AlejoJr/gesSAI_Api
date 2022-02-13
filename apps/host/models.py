from django.db import models
from django.contrib.auth.models import User


# Create your models here.
class Host(models.Model):
    """
      Modelo de datos de los Host
    """
    name_host = models.CharField(max_length=100, null=True, blank=True)
    ip = models.GenericIPAddressField(null=True)
    mac = models.CharField(max_length=100, null=True, default="")
    so = models.CharField(max_length=1)
    group = models.ForeignKey('group.Group', related_name='host', on_delete=models.CASCADE, null=True)
    order = models.CharField(max_length=50, null=True)
    description = models.TextField(null=True, blank=True)
    pool = models.ForeignKey('pool.Pool', related_name='host', on_delete=models.CASCADE, null=True)
    user = models.ForeignKey(User, related_name='host', on_delete=models.CASCADE)
    #user = models.ForeignKey('user.User', related_name='host', on_delete=models.CASCADE)
    type_host = models.CharField(max_length=20, null=True)


    class Meta:
        db_table = 'HOST'

    def __str__(self):
        return '{}'.format(self.name_host)
