from rest_framework import serializers

from apps.host.models import Host
from apps.group.models import Group
from apps.group.api.serializers import GroupSerializer


class HostSerializer(serializers.ModelSerializer):
    group = GroupSerializer(read_only=True)
    groupId = serializers.PrimaryKeyRelatedField(write_only=True, queryset=Group.objects.all(),source='group', allow_null=True)

    class Meta:
        model = Host
        fields = ('id', 'name_host', 'ip', 'mac', 'so', 'group', 'groupId', 'order', 'description', 'pool', 'user', 'type_host')
