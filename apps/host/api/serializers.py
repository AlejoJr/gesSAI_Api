from rest_framework import serializers

from apps.host.models import Host
from apps.group.models import Group
from apps.pool.models import Pool
from apps.group.api.serializers import GroupSerializer
from apps.pool.api.serializers import PoolSerializer


class HostSerializer(serializers.ModelSerializer):
    group = GroupSerializer(read_only=True)
    groupId = serializers.PrimaryKeyRelatedField(write_only=True, queryset=Group.objects.all(),source='group', allow_null=True)
    pool = PoolSerializer(read_only=True)
    poolId = serializers.PrimaryKeyRelatedField(write_only=True, queryset=Pool.objects.all(), source='pool',allow_null=True)

    class Meta:
        model = Host
        fields = ('id', 'name_host', 'ip', 'mac', 'so', 'group', 'groupId', 'order', 'description', 'pool', 'poolId', 'user', 'type_host', 'sais')
