from rest_framework import serializers

from apps.pool.models import Pool


class PoolSerializer(serializers.ModelSerializer):
    class Meta:
        model = Pool
        fields = '__all__'
