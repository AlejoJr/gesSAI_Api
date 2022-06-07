from rest_framework import serializers

from apps.host import apps
from apps.host.models import Host, HostSai, Dependence
from apps.group.models import Group
from apps.sai.models import Sai
from apps.pool.models import Pool
from apps.group.api.serializers import GroupSerializer
from apps.pool.api.serializers import PoolSerializer
from apps.sai.api.serializers import SaiSerializer


class HostSaiSerializer(serializers.ModelSerializer):
    class Meta:
        model = HostSai
        fields = '__all__'


class DependenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Dependence
        fields = '__all__'


class HostChildrenSerializer(serializers.ModelSerializer):
    class Meta:
        model = Host
        fields = ('id', 'name_host', 'type_host', 'sais')


class HostSerializer(serializers.ModelSerializer):
    value = serializers.CharField(source='id', read_only=True) #Solo es para leer
    label = serializers.CharField(source='name_host', read_only=True) #Solo es para leer
    group = GroupSerializer(read_only=True)
    groupId = serializers.PrimaryKeyRelatedField(write_only=True, queryset=Group.objects.all(),source='group', allow_null=True)
    pool = PoolSerializer(read_only=True)
    poolId = serializers.PrimaryKeyRelatedField(write_only=True, queryset=Pool.objects.all(), source='pool', allow_null=True)
    host_host = HostChildrenSerializer(many=True)

    class Meta:
        model = Host
        fields = ('id', 'value', 'label', 'name_host', 'ip', 'mac', 'so', 'group', 'groupId', 'order', 'description', 'pool', 'poolId', 'user', 'type_host', 'sais', 'host_host')


