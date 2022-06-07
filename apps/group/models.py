from django.db import models
#from django.contrib.auth.models import User
from apps.user.models import User
from apps.host.models import Host


# Create your models here.
class Group(models.Model):
    """
      Modelo de datos del Group
    """
    name_group = models.CharField(max_length=100, null=True)
    user = models.ForeignKey(User, related_name='group', on_delete=models.CASCADE, null=True)

    class Meta:
        db_table = 'GROUP'

    def __str__(self):
        return '{}'.format(self.name_group)
