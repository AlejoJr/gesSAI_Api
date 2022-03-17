from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import viewsets, status
from rest_framework.views import APIView

from django.shortcuts import get_object_or_404
from django.db.models import Q

from apps.host.api.serializers import HostSerializer
from apps.host.api.helpers import selectSQL

from apps.host.models import Host
from apps.group.models import Group


class HostViewSet(viewsets.ModelViewSet):
    """Clase que contiene los metodos genericos para la vista de los Hosts
    ['get', 'post', 'put', 'delete']"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = HostSerializer

    def get_queryset(self, pk=None):
        if pk is None:
            return self.get_serializer().Meta.model.objects.filter(
                user_id=self.request.user.pk)  # -->Filtro los Host por el usuario que esta en session
        return self.get_serializer().Meta.model.objects.filter(id=pk).first()

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            host = Host.objects.filter(name_host=serializer.initial_data['name_host']).filter(ip=serializer.initial_data['ip']).exists()

            if host:
                return Response("Im Used", status=status.HTTP_226_IM_USED)
            else:
                serializer.save()
                # return Response({'message': 'Host creado correctamente!'}, status=status.HTTP_201_CREATED)
                return Response("Created-OK", status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None, *args, **kwargs):
        if self.get_queryset(pk):
            host_serializer = self.serializer_class(self.get_queryset(pk), data=request.data)
            if host_serializer.is_valid():
                host_serializer.save()
                # return Response(host_serializer.data, status=status.HTTP_200_OK)
                return Response("Updated-OK", status=status.HTTP_200_OK)
            return Response(host_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None, *args, **kwargs):
        host = self.get_queryset().filter(id=pk).first()
        if host:
            host.delete()
            return Response({'message': 'Host eliminado correctamente!'}, status=status.HTTP_200_OK)
        return Response({'error': 'No existe el Host para eliminarlo'}, status=status.HTTP_400_BAD_REQUEST)


class getHost_ExistMachineView(APIView):
    """Clase que comprueba si existe la maquina en la base de datos externa"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = HostSerializer

    def post(self, request, *args, **kwargs):
        """
        Comprueba si existe la maquina con el nombre que llega por parametro
        :param request peticion de consulta (nombre de maquina DNS)
        """

        nameMachine = request.data['name']

        sql = "select distinct nombre,mac,ip1,ip2,ip3,ip4 from PLAQUES.TAR_HOSTS_FISICA_DSIC@ALUMNADO.DSIC.UPV.ES WHERE NOMBRE = '" + nameMachine.lower() + "';"

        responseQuery = selectSQL(sql, None, 'bdoracle')

        if responseQuery:
            mac = ':'.join(format(s, '02x') for s in bytes.fromhex(responseQuery[0][1]))
            ip = str(responseQuery[0][2]) + "." + str(responseQuery[0][3]) + "." + str(responseQuery[0][4]) + "." + str(
                responseQuery[0][5])

            data_machine = {'name_host': responseQuery[0][0], 'ip': ip, 'mac': mac}
            return Response(data_machine, status=status.HTTP_200_OK)
        else:
            return Response('not found machine', status=status.HTTP_200_OK)


class getHostsByGroup(APIView):
    """Clase que retorna todos los hosts de un grupo"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = HostSerializer

    def post(self, request, *args, **kwargs):
        """
        Retorna los hosts del grupo
        :param request peticion de consulta (idGroup)
        """

        groupId = request.data['idGroup']

        group = get_object_or_404(Group, pk=groupId)
        nameGroup = group.name_group
        hosts = Host.objects.filter(group_id=groupId)

        if hosts:
            result = {'nameGroup': nameGroup, 'hosts': hosts.values()}
            return Response(result, status=status.HTTP_200_OK)
        else:
            return Response('El grupo no tiene máquinas', status=status.HTTP_200_OK)


class getMasterHosts(APIView):
    """Clase que retorna todos los hosts master de tipo (HM) = HOST MASTER"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = HostSerializer

    def post(self, request, *args, **kwargs):
        """
        Retorna el Host Master asociado a cada Pool del usuario
        :param request peticion de consulta (idUser)
        """

        userId = request.data['idUser']

        hostsMaster = Host.objects.filter(user_id=userId).filter(type_host='HM')

        hostsOthers = Host.objects.filter(user_id=userId).filter(type_host='HO')

        serializer = HostSerializer(hostsMaster, many=True)
        serializer_others = HostSerializer(hostsOthers, many=True)

        if hostsMaster:
            result = {'hosts': serializer.data, 'others': serializer_others.data}
            return Response(result, status=status.HTTP_200_OK)
        else:
            return Response('Without-Machines', status=status.HTTP_200_OK)

class getHostsOfMasterHost(APIView):
    """Clase que retorna todos los hosts de un (pool - hostmaster) de tipo (HO) = HOST OTHER"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = HostSerializer

    def post(self, request, *args, **kwargs):
        """
        Retorna los Hosts asociados a un Pool (Host Master)
        :param request peticion de consulta (idPool)
        """

        poolId = request.data['idPool']

        hosts = Host.objects.filter(pool_id=poolId).filter(type_host='HO')

        serializer = HostSerializer(hosts, many=True)

        if hosts:
            result = {'hosts': serializer.data}
            return Response(result, status=status.HTTP_200_OK)
        else:
            return Response('Without-Machines', status=status.HTTP_200_OK)


class getAllHostsInAGroup(APIView):
    """Clase que retorna todos los hosts que estan en un grupo"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = HostSerializer

    def get(self, request, *args, **kwargs):
        """
        Retorna todos los host que tienen grupo
        """

        hosts = Host.objects.filter(~Q(group_id=None))

        serializer = HostSerializer(hosts, many=True)

        if hosts:
            result = {'hosts': serializer.data}
            return Response(result, status=status.HTTP_200_OK)
        else:
            return Response('Without-Machines', status=status.HTTP_200_OK)


class getHostByName(APIView):
    """Clase que retorna una maquina por su nombre"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = HostSerializer

    def post(self, request, *args, **kwargs):
        """
        Retorna el Host si se encuentra
        :param request peticion de consulta (nameHost)
        """

        hostName = request.data['nameHost']

        host = Host.objects.filter(name_host=hostName)

        serializer = HostSerializer(host, many=True)

        if host:
            result = {'host': serializer.data}
            return Response(result, status=status.HTTP_200_OK)
        else:
            return Response('Not Exists Machine', status=status.HTTP_200_OK)
