from rest_framework import serializers

from apps.sai.models import Sai
#from apps.user.models import User
from apps.user.api.serializers import UserSerializer, User


class SaiSerializer(serializers.ModelSerializer):

    class Meta:
        model = Sai
        fields = ('id', 'name_sai', 'userConnection', 'authKey', 'privKey', 'ip', 'mac', 'url', 'protocol', 'state', 'code_oid', 'value_off', 'value_on', 'administrator')
