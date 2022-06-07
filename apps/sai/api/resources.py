import sys

from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import viewsets, status
from rest_framework.views import APIView

from apps.backend.utils import get_env_setting
from apps.host.api.helpers import selectSQL
from apps.host.management.commands.turnOffMachine import batteryLevel
from apps.sai.api.serializers import SaiSerializer

from pysnmp.hlapi import *
import cryptocode

from apps.sai.models import Sai


class SaiViewSet(viewsets.ModelViewSet):
    """Clase que contiene los metodos genericos para la vista de los Sai
    ['get', 'post', 'put', 'delete']"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = SaiSerializer

    def get_queryset(self, pk=None):
        if pk is None:
            return self.get_serializer().Meta.model.objects.all()
        return self.get_serializer().Meta.model.objects.filter(id=pk).first()

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            sai = Sai.objects.filter(name_sai=serializer.initial_data['name_sai']).filter(mac=serializer.initial_data['mac']).exists()

            if sai:
                return Response('Im-Used', status=status.HTTP_226_IM_USED)
            else:
                passAuthKey = request.data['authKey']
                passPrivKey = request.data['privKey']

                # Cifrar contraseñas
                semilla = get_env_setting('SEMILLA')
                passAuthKey_encoded = cryptocode.encrypt(passAuthKey, semilla)
                passPrivKey_encoded = cryptocode.encrypt(passPrivKey, semilla)

                objSai = Sai(name_sai=request.data['name_sai'],
                             userConnection=request.data['userConnection'],
                             authKey=passAuthKey_encoded,
                             privKey=passPrivKey_encoded,
                             ip=request.data['ip'],
                             mac=request.data['mac'],
                             url=request.data['url'],
                             protocol=request.data['protocol'],
                             state=request.data['state'],
                             code_oid=request.data['code_oid'],
                             value_off=request.data['value_off'],
                             value_on=request.data['value_on'],
                             administrator_id=request.data['administrator'])

                objSai.save()
                #serializer.save()
                return Response('Created-OK', status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None, *args, **kwargs):
        if self.get_queryset(pk):
            sai_serializer = self.serializer_class(self.get_queryset(pk), data=request.data)
            if sai_serializer.is_valid():
                updateSai = Sai(
                    id=sai_serializer.initial_data['id'],
                    name_sai=sai_serializer.initial_data['name_sai'],
                    userConnection=sai_serializer.initial_data['userConnection'],
                    authKey=sai_serializer.initial_data['authKey'],
                    privKey=sai_serializer.initial_data['privKey'],
                    ip=sai_serializer.initial_data['ip'],
                    mac=sai_serializer.initial_data['mac'],
                    url=sai_serializer.initial_data['url'],
                    protocol=sai_serializer.initial_data['protocol'],
                    state=sai_serializer.initial_data['state'],
                    administrator_id=sai_serializer.initial_data['administrator'],
                    code_oid=sai_serializer.initial_data['code_oid'],
                    value_off=sai_serializer.initial_data['value_off'],
                    value_on=sai_serializer.initial_data['value_on'])
                updateSai.save()
                return Response("Updated-OK", status=status.HTTP_200_OK)
            return Response(sai_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None, *args, **kwargs):
        sai = self.get_queryset().filter(id=pk).first()
        if sai:
            sai.delete()
            return Response({'message': 'Sai eliminado correctamente!'}, status=status.HTTP_200_OK)
        return Response({'error': 'No existe el Sai para eliminarlo'}, status=status.HTTP_400_BAD_REQUEST)


class tryConnectionSAI(APIView):
    """Clase que prueba la conexión a un SAI"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = SaiSerializer

    def post(self, request, *args, **kwargs):
        """
        Retorna OK si la conexión al SAI es exitosa, ERROR si la conexión falla.
        :param request peticion de consulta (sai)
        """

        nameSai = request.data['name_sai']
        responseExistsMachine = existMachine(nameSai)

        if responseExistsMachine['exists'] == 'No':
            return Response(responseExistsMachine, status=status.HTTP_203_NON_AUTHORITATIVE_INFORMATION)


        userConnection = request.data['userConnection']
        authKey = request.data['authKey']
        privKey = request.data['privKey']
        url = request.data['url'].replace('http://', '').replace('https://', '')
        code_oid = request.data['code_oid']

        responseConnection = connectionSai(userConnection, authKey, privKey, url, code_oid)

        if responseConnection['Connection'] == 'OK':
            responseConnection['ip'] = responseExistsMachine['ip']
            responseConnection['mac'] = responseExistsMachine['mac']
            return Response(responseConnection, status=status.HTTP_200_OK)
        else:
            return Response(responseConnection, status=status.HTTP_204_NO_CONTENT)


class getBatterySai(APIView):
    """Clase que devuelve la bateria restante de los SAIS"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = SaiSerializer

    def post(self, request, *args, **kwargs):
        """
        Retorna la bateria restante de cada sai.
        :param request peticion de consulta (sais)
        """

        nameSai = request.data['name_sai']
        url_sai = request.data['url'].replace('http://', '').replace('https://', '')
        user_sai = request.data['userConnection']
        authKey_sai = request.data['authKey']
        privKey_sai = request.data['privKey']
        code_oid = request.data['code_oid']

        # Desencriptamos las claves
        semilla = get_env_setting('SEMILLA')
        authKey_decoded = cryptocode.decrypt(authKey_sai, semilla)
        privKey_decoded = cryptocode.decrypt(privKey_sai, semilla)

        levelBattery = batteryLevel(user_sai, authKey_decoded, privKey_decoded, url_sai, code_oid)

        return Response(levelBattery, status=status.HTTP_200_OK)


def connectionSai(user, authKey, privKey, host, oid):
    connection = ''
    code = ''

    try:
        iterator = getCmd(
            SnmpEngine(),
            UsmUserData(user, authKey=authKey, privKey=privKey),
            UdpTransportTarget((host, 161)),
            ContextData(),
            # ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            ObjectType(ObjectIdentity(oid))
        )

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        if errorIndication:
            connection = 'ERROR'
            print('Error connection SAI: ', errorIndication)

        elif errorStatus:
            connection = 'ERROR'
            print('Error connection SAI.')
            print('%s at %s' % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))

        else:
            for varBind in varBinds:
                connection = 'OK'
                code = str(varBind[0].prettyPrint())

        responseSai = {'Connection': connection, 'Code': code}

        return responseSai

    except Exception:
        e = sys.exc_info()[1]
        print('Ocurrio un (except) ERROR al conectar con el SAI: ', e)
        return {'Connection': 'ERROR', 'Code': str(e)}


def existMachine(nameSai):
    """Metodo que comprueba si existe la maquina en la base de datos externa"""

    sql = "select distinct nombre,mac,ip1,ip2,ip3,ip4 from PLAQUES.TAR_HOSTS_FISICA_DSIC@ALUMNADO.DSIC.UPV.ES WHERE NOMBRE = '" + nameSai.lower() + "';"

    responseQuery = selectSQL(sql, None, 'bdoracle')

    if responseQuery:
        mac = ':'.join(format(s, '02x') for s in bytes.fromhex(responseQuery[0][1]))
        ip = str(responseQuery[0][2]) + "." + str(responseQuery[0][3]) + "." + str(responseQuery[0][4]) + "." + str(
            responseQuery[0][5])

        return {'exists': 'Yes', 'name_host': responseQuery[0][0], 'ip': ip, 'mac': mac}
    else:
        return {'exists': 'No'}