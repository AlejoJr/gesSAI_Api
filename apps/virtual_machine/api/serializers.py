from rest_framework import serializers

from apps.virtual_machine.models import VirtualMachine


class VirtualMachineSerializer(serializers.ModelSerializer):
    class Meta:
        model = VirtualMachine
        fields = '__all__'
