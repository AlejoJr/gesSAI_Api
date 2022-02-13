from django.db import models

# Create your models here.
class Sai(models.Model):
    """
      Modelo de datos de los SAI
    """
    ip = models.GenericIPAddressField(null=True)
    name_sai = models.CharField(max_length=100)
    url = models.URLField(null=True)
    type = models.CharField(max_length=1)
    state = models.CharField(max_length=50)
    responsible = models.CharField(max_length=100)
    code_oid = models.CharField(max_length=100)
    value_off = models.CharField(max_length=50)
    value_on = models.CharField(max_length=50)

    class Meta:
        db_table = 'SAI'

    def __str__(self):
        return '{}'.format(self.name_sai)