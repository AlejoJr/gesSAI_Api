from django.db import models

from apps.backend.hipervisor_api.xenapi import conection


# Create your models here.
sessions = {}
class Pool(models.Model):
    """
      Modelo de datos de los Pool
    """
    name_pool = models.CharField(max_length=100, null=True)
    ip = models.GenericIPAddressField(null=True)
    url = models.URLField(null=True, blank=True)
    username = models.CharField(max_length=100, null=True)
    type = models.CharField(max_length=1, null=False)

    class Meta:
        db_table = 'POOL'

    def __str__(self):
        return '{}'.format(self.name_pool)

    @property
    def cache_key(self):
        return "pool_session_{}".format(self.pk)

    @property
    def session(self):
        """":return  session de Xen o Ovirt"""

        session = sessions.get(self.cache_key)
        if not session:
            session = conection(url=self.url, user=self.username, hipervisor_type=self.type)
            sessions[self.cache_key] = session
        return session