from django.db import models


# Create your models here.
class VirtualMachine(models.Model):
    """
      Modelo de datos de la Virtual Machine
    """
    uuid = models.CharField(max_length=100, null=True, blank=True)
    ref = models.CharField(max_length=100, null=True, blank=True)
    name = models.CharField(max_length=100, null=True, blank=True)
    type = models.CharField(max_length=3)
    ip = models.GenericIPAddressField(null=True)
    mac = models.CharField(max_length=100, null=True, default="")
    power_state = models.CharField(max_length=50, null=True, default="")
    so = models.CharField(max_length=1)
    description = models.TextField(null=True)
    order = models.CharField(max_length=50)
    pool = models.ForeignKey('pool.Pool', related_name='virtual_machine', on_delete=models.CASCADE)

    class Meta:
        db_table = 'VIRTUAL_MACHINE'

    def __str__(self):
        return '{}'.format(self.name)
