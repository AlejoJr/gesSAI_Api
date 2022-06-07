from rest_framework import serializers

from apps.pool.models import Pool
from apps.sai.models import Sai
from apps.sai.api.serializers import SaiSerializer


class PoolSerializer(serializers.ModelSerializer):
    value = serializers.CharField(source='id', read_only=True)  # Solo es para leer
    label = serializers.CharField(source='name_pool', read_only=True)  # Solo es para leer
    class Meta:
        model = Pool
        fields = ('id', 'value', 'label', 'name_pool', 'ip', 'url', 'username', 'password', 'type', 'user', 'sais')
