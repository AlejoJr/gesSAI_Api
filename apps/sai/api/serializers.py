from rest_framework import serializers

from apps.sai.models import Sai


class SaiSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sai
        fields = '__all__'
