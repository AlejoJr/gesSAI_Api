from rest_framework import serializers

from apps.pool.models import Pool
from apps.sai.models import Sai
from apps.sai.api.serializers import SaiSerializer


class PoolSerializer(serializers.ModelSerializer):
    class Meta:
        model = Pool
        fields = '__all__'
