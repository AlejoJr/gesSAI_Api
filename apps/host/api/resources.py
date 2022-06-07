import os

from django.http import FileResponse
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import viewsets, status
from rest_framework.views import APIView

from django.shortcuts import get_object_or_404
from django.db.models import Q
from django.conf import settings
from django.http import HttpResponse

from apps.host.api.serializers import HostSerializer
from apps.host.api.helpers import selectSQL

from apps.host.models import Host, HostSai, Dependence
from apps.pool.models import Pool
from apps.sai.models import Sai
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
            host = Host.objects.filter(name_host=serializer.initial_data['name_host']).filter(
                ip=serializer.initial_data['ip']).exists()

            if host:
                return Response("Im Used", status=status.HTTP_226_IM_USED)
            else:
                objHost = Host(name_host=serializer.initial_data['name_host'],
                               ip=serializer.initial_data['ip'],
                               mac=serializer.initial_data['mac'],
                               so=serializer.initial_data['so'],
                               description=serializer.initial_data['description'],
                               type_host=serializer.initial_data['type_host'],
                               pool_id=serializer.initial_data['poolId'],
                               user_id=serializer.initial_data['user'])
                objHost.save()

                idSais = []

                if serializer.initial_data['type_host'] == 'MV':
                    objPool = Pool.objects.get(id=serializer.initial_data['poolId'])
                    for sai in objPool.sais.all():
                        idSais.append(sai.id)
                elif serializer.initial_data['type_host'] == 'MF' or serializer.initial_data['type_host'] == 'SM':
                    idSais = serializer.initial_data['sais']

                for idSai in idSais:
                    sai = Sai.objects.get(id=idSai)
                    m1 = HostSai(host=objHost, sai=sai, enchufado=True)
                    m1.save()

                # serializer.save()
                # return Response({'message': 'Host creado correctamente!'}, status=status.HTTP_201_CREATED)
                return Response("Created-OK", status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None, *args, **kwargs):
        if self.get_queryset(pk):
            host_serializer = self.serializer_class(self.get_queryset(pk), data=request.data)
            if host_serializer.is_valid():
                updateHost = Host(
                    id=host_serializer.initial_data['id'],
                    name_host=host_serializer.initial_data['name_host'],
                    ip=host_serializer.initial_data['ip'],
                    mac=host_serializer.initial_data['mac'],
                    so=host_serializer.initial_data['so'],
                    type_host=host_serializer.initial_data['type_host'],
                    pool_id=host_serializer.initial_data['poolId'],
                    description=host_serializer.initial_data['description'],
                    user_id=host_serializer.initial_data['user'], )
                updateHost.save()

                idSais = host_serializer.initial_data['sais']
                objHostSais = HostSai.objects.filter(host=updateHost, enchufado=True)

                for objSai in objHostSais:
                    if objSai.sai_id not in idSais:
                        objSai.delete()

                for idSai in idSais:
                    sai = Sai.objects.get(id=idSai)
                    obj, created = HostSai.objects.update_or_create(host=updateHost, sai=sai, enchufado=True)

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


class createDependence(APIView):
    """Clase que crea la dependencia de maquinas"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = HostSerializer

    def post(self, request, *args, **kwargs):
        """
        Retorna la creacion de la dependencia
        :param request peticion de consulta (hostFather, hostChild)
        """
        try:
            hostFather = request.data['hostFather']
            hostChild = request.data['hostChild']
            isNewFather = False
            idSaisFather = []
            hostVmFather = ''
            isNewChild = False
            idSaisChild = []
            hostVmChild = ''

            if hostFather['type_host'] == 'MV':
                objHostFather = Host.objects.filter(name_host=hostFather['name_host']).filter(
                    pool_id=hostFather['pool_id']).first()
                if objHostFather is None:
                    hostVmFather = Host(name_host=hostFather['name_host'],
                                        type_host=hostFather['type_host'],
                                        pool_id=hostFather['pool_id'],
                                        user_id=request.user.pk)
                    hostVmFather.save()
                    objHostFather = hostVmFather
                    isNewFather = True

                objPool = Pool.objects.get(id=hostFather['pool_id'])
                for sai in objPool.sais.all():
                    idSaisFather.append(sai.id)

            elif hostFather['type_host'] == 'MF' or hostFather['type_host'] == 'HM' or hostFather['type_host'] == 'SM':
                idSaisFather = hostFather['sais']
                objHostFather = Host.objects.filter(name_host=hostFather['name_host']).filter(
                    ip=hostFather['ip']).first()

            if isNewFather:
                for idSai in idSaisFather:
                    sai = Sai.objects.get(id=idSai)
                    m1 = HostSai(host=hostVmFather, sai=sai, enchufado=True)
                    m1.save()

            if hostChild['type_host'] == 'MV':
                objHostChild = Host.objects.filter(name_host=hostChild['name_host']).filter(
                    pool_id=hostChild['pool_id']).first()

                if objHostChild is None:
                    hostVmChild = Host(name_host=hostChild['name_host'],
                                       type_host=hostChild['type_host'],
                                       pool_id=hostChild['pool_id'],
                                       user_id=request.user.pk)
                    hostVmChild.save()
                    objHostChild = hostVmChild

                    isNewChild = True

                objPool = Pool.objects.get(id=hostChild['pool_id'])
                for sai in objPool.sais.all():
                    idSaisChild.append(sai.id)

            elif hostChild['type_host'] == 'MF' or hostChild['type_host'] == 'HM' or hostChild['type_host'] == 'SM':
                idSaisChild = hostChild['sais']
                objHostChild = Host.objects.filter(name_host=hostChild['name_host']).filter(ip=hostChild['ip']).first()

            if isNewChild:
                for idSai in idSaisChild:
                    sai = Sai.objects.get(id=idSai)
                    m1 = HostSai(host=hostVmChild, sai=sai, enchufado=True)
                    m1.save()

            altaSaiNoEnchufado(objHostChild, idSaisFather, objHostFather)

            # Creamos la dependencia Padre - Hijo
            dependence = Dependence(cod_father=objHostFather, cod_child=objHostChild, finished_child=False,
                                    finished_father=False)
            dependence.save()

            moreFathers = Dependence.objects.filter(cod_child=objHostChild).exclude(cod_father=objHostFather)
            for father in moreFathers:
                deleteDependenceOfOtherFather(objHostFather, objHostChild, father.cod_father, father.cod_child, True,
                                              father)

            return Response("Created-OK", status=status.HTTP_200_OK)

        except:
            return Response("Error-dependence", status=status.HTTP_400_BAD_REQUEST)


def deleteDependenceOfOtherFather(objFirtsFather, objFirtsChild, objAuxFather, objAuxChild, firtsTime, father):
    if firtsTime:
        moreChildren = Dependence.objects.filter(cod_father=objAuxFather).exclude(cod_child=objFirtsChild)
    else:
        moreChildren = Dependence.objects.filter(cod_father=objAuxFather)

    for children in moreChildren:
        if children.cod_child == objFirtsFather:
            father.delete()
        else:
            deleteDependenceOfOtherFather(objFirtsFather, objFirtsChild, children.cod_child, objAuxChild, False, father)


# Metodo recursivo
def altaSaiNoEnchufado(objHostChild, idSaisFather, objHostFather):
    sais_child = []
    for saiChild in objHostChild.sais.all():
        sais_child.append(saiChild.id)

    sais_father = []
    for saiFather in objHostFather.sais.all():
        sais_father.append(saiFather.id)

    # Obtener la diferencia de los sai del Padre y el Hijo (SAIs - NO ENCHUFADOS)
    set_difference = set(sais_father).symmetric_difference(set(sais_child))
    list_difference = list(set_difference)

    for idSai in list_difference:
        if idSai not in sais_child:
            sai = Sai.objects.get(id=idSai)
            m1 = HostSai(host=objHostChild, sai=sai, enchufado=False)
            m1.save()

    children = Dependence.objects.filter(cod_father=objHostChild)

    for child in children:
        print("  ", objHostChild, ': Padre de ->', child.cod_child)
        altaSaiNoEnchufado(child.cod_child, idSaisFather, objHostFather)


class getChildrenFromFather(APIView):
    """Clase que retorna las maquinas hijos de un padre"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = HostSerializer

    def post(self, request, *args, **kwargs):
        """
        Retorna las maquinas (Host) Hijos de un Padre
        :param request peticion de consulta (hostFather)
        """
        host = False
        hostFather = request.data['hostFather']

        if hostFather['type_host'] == 'MV':
            host = Host.objects.filter(name_host=hostFather['name_host'], type_host=hostFather['type_host'],
                                       pool_id=hostFather['pool_id'], user_id=request.user.pk).first()
        elif hostFather['type_host'] == 'HM' or hostFather['type_host'] == 'MF' or hostFather['type_host'] == 'SM':
            host = Host.objects.filter(id=hostFather['id']).first()

        if host:
            children = Dependence.objects.filter(cod_father=host)
            # Obtener los hijos del host
            hosts = []
            for objDependence in children:
                hosts.append(objDependence.cod_child)

            # Obtener los hijos de mis hijos
            listChildFromChildren = []
            objChilds = searchChildFromChildren(host, listChildFromChildren)

            if hosts:
                serializer = HostSerializer(hosts, many=True)
                result = {'hosts': serializer.data, 'childrens': listChildFromChildren}
                return Response(result, status=status.HTTP_200_OK)
            else:
                return Response('Not Exist Children', status=status.HTTP_200_OK)
        else:
            return Response('Not Exist Machine', status=status.HTTP_200_OK)


# Metodo recursivo
def searchChildFromChildren(host, listChildFromChildren):
    dependences = Dependence.objects.filter(cod_father=host)
    for dependence in dependences:
        listChildFromChildren.append(dependence.cod_child.name_host)
        objList = searchChildFromChildren(dependence.cod_child, listChildFromChildren)

    return listChildFromChildren


class getParentsFromParent(APIView):
    """Clase que retorna los Padres de una Maquina y los padres de sus padres"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = HostSerializer

    def post(self, request, *args, **kwargs):
        """
        Retorna las maquinas (Host) Padres de un Hijo
        :param request peticion de consulta (hostChild)
        """

        host = False
        hostChild = request.data['hostChild']

        if hostChild['type_host'] == 'MV':
            host = Host.objects.filter(name_host=hostChild['name_host'], type_host=hostChild['type_host'],
                                       pool_id=hostChild['pool_id'], user_id=request.user.pk).first()
        elif hostChild['type_host'] == 'HM':
            host = Host.objects.filter(id=hostChild['id']).first()
        elif hostChild['type_host'] == 'MF':
            host = Host.objects.filter(id=hostChild['id']).first()

        if host:
            listFathers = []
            objChilds = searchFathersDependence(host, listFathers)

            if listFathers:
                result = {'hosts': listFathers}
                return Response(result, status=status.HTTP_200_OK)
            else:
                return Response('Not Exist Fathers', status=status.HTTP_200_OK)
        else:
            return Response('Not Exist Machine', status=status.HTTP_200_OK)


# Metodo recursivo
def searchFathersDependence(host, listFathers):
    fathers = Dependence.objects.filter(cod_child=host)
    for father in fathers:
        listFathers.append(father.cod_father.name_host)
        objList = searchFathersDependence(father.cod_father, listFathers)

    return listFathers


class getTreeDependence(APIView):
    """Clase que retorna el arbol de dependencias del Host"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = HostSerializer

    def post(self, request, *args, **kwargs):
        """
        Retorna el Arbol de dependencias del Host
        :param request peticion de consulta (idHostFather)
        """

        hostFather = request.data['hostFather']

        tree = {
            "id": "root",
            "name": hostFather['name_host'],
            "children": []
        }

        if hostFather['type_host'] == 'MF' or hostFather['type_host'] == 'HM' or hostFather['type_host'] == 'SM':
            objChilds = searchChildsDependence(hostFather['id'], tree)
            tree["children"] = objChilds
        elif hostFather['type_host'] == 'MV':
            try:
                if 'pool_id' in hostFather:
                    objMv = Host.objects.get(name_host=hostFather['name_host'], pool_id=hostFather['pool_id'],
                                             type_host=hostFather['type_host'])
                else:
                    objMv = Host.objects.get(name_host=hostFather['name_host'], pool_id=hostFather['pool']['id'],
                                             type_host=hostFather['type_host'])

                objChilds = searchChildsDependence(objMv.id, tree)
                tree["children"] = objChilds
            except:
                tree["children"] = []

        return Response(tree, status=status.HTTP_200_OK)


# Metodo recursivo
def searchChildsDependence(idHostFather, objTree):
    objDependence = Dependence.objects.filter(cod_father_id=idHostFather)
    list = []
    for child in objDependence:
        idChild = child.id
        nameChild = child.cod_child.name_host
        objChild = {"id": str(idChild), "name": nameChild, "children": []}

        list.append(objChild)
        objTree["children"] = list
        objList = searchChildsDependence(child.cod_child.id, objChild)

    return list


class deleteDependence(APIView):
    """Clase que Elimina las dependencias existentes."""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = HostSerializer

    def post(self, request, *args, **kwargs):
        """
        Retorna el Ok si la dependencia fue eliminada correctamente
         :param request peticion de consulta (hostFather, hostChild)
        """
        try:
            hostFather = request.data['hostFather']
            hostChild = request.data['hostChild']

            idFather = hostFather['id']
            idChild = hostChild['id']

            if hostFather['type_host'] == 'MV':
                objMv = Host.objects.get(name_host=hostFather['name_host'], pool_id=hostFather['pool_id'],
                                         type_host=hostFather['type_host'])
                idFather = objMv.id

            if hostChild['type_host'] == 'MV':
                if "pool_id" in hostChild:
                    objMv = Host.objects.get(name_host=hostChild['name_host'], pool_id=hostChild['pool_id'],
                                             type_host=hostChild['type_host'])
                    idChild = objMv.id
                else:
                    idChild = hostChild['id']

            objDependence = Dependence.objects.filter(cod_father_id=idFather, cod_child=idChild)

            objDependence.delete()

            deleteNoEnchufado(idFather, idChild, None)

            # Si el host es maquina virtual se valida que NO tenga ninguna dependencia para eliminarlo de la BD
            if hostFather['type_host'] == 'MV':
                deleteMachineVirtual(idFather)
            if hostChild['type_host'] == 'MV':
                deleteMachineVirtual(idChild)

            return Response("Delete-OK", status=status.HTTP_200_OK)

        except:
            return Response("Error-delete-dependence", status=status.HTTP_400_BAD_REQUEST)


# Metodo recursivo
def deleteNoEnchufado(idHostFather, idHostChild, saisFirtsFather=None):
    responseValidate = validateMoreFathers(idHostFather, idHostChild)

    if responseValidate == False:
        # True solo la primera ronda
        if saisFirtsFather is None:
            # <-- Obtener los SAIS enchufados del Padre -->
            objHostSaiFather_true = HostSai.objects.filter(host_id=idHostFather, enchufado=True)

            sais_father_true = []
            for saiFather in objHostSaiFather_true:
                sais_father_true.append(saiFather.sai.id)

            saisFirtsFather = sais_father_true

            # <-- Obtener los SAIS NO enchufados del Hijo -->
            objHostSaiChild_false = HostSai.objects.filter(host_id=idHostChild, enchufado=False)

            for hostSai in objHostSaiChild_false:
                if hostSai.sai_id in saisFirtsFather:
                    hostSai.delete()

            # Recursividad para ver si el hijo tiene mas hijos
            children = Dependence.objects.filter(cod_father_id=idHostChild)

            for child in children:
                deleteNoEnchufado(idHostChild, child.cod_child.id, saisFirtsFather)
        else:
            # <-- Obtener Todos los SAIS del Padre (enchufados o no) -->
            objHostSaiFather_all = HostSai.objects.filter(host_id=idHostFather)

            sais_father_all = []
            for saiFather in objHostSaiFather_all:
                sais_father_all.append(saiFather.sai.id)

            # <-- Obtener los SAIS NO enchufados del Hijo -->
            objHostSaiChild_false = HostSai.objects.filter(host_id=idHostChild, enchufado=False)

            # Comparo los SAIS del primer padre con los del hijo
            for hostSai in objHostSaiChild_false:
                if hostSai.sai_id in saisFirtsFather:
                    # Eliminamos el SAI No enchufado solo si no se encuentra entre los SAIS del padre
                    if hostSai.sai_id not in sais_father_all:
                        hostSai.delete()

            # Recursividad para ver si el hijo tiene mas hijos
            children = Dependence.objects.filter(cod_father_id=idHostChild)

            for child in children:
                deleteNoEnchufado(idHostChild, child.cod_child.id, saisFirtsFather)


def validateMoreFathers(idHostFather, idHostChild):
    # <-- Ver si el Hijo tiene mas Padres -->
    moreFathers = Dependence.objects.filter(cod_child_id=idHostChild).exclude(cod_father_id=idHostFather)

    # <-- Logica para identificar si los demas padres estan asociados al mismo SAI que quiero eliminar -->
    # <-- Si almenos un padre esta asociado, NO elimino la relacion. -->
    equalSai = False
    for father in moreFathers:
        # <-- Obtener Todos los SAIS del Padre (enchufados o no) -->
        objSaiFather = HostSai.objects.filter(host_id=father.cod_father.id)

        sais_father = []
        for saiFather in objSaiFather:
            sais_father.append(saiFather.sai.id)

        # <-- Obtener los SAIS NO enchufados del Hijo -->
        objHostSaiChild_false = HostSai.objects.filter(host_id=idHostChild, enchufado=False)

        for hostSai in objHostSaiChild_false:
            if hostSai.sai_id in sais_father:
                equalSai = True

    return equalSai


def deleteMachineVirtual(idMachineVirtual):
    # Validamos que NO aparezca como padre
    isDependenceFather_Father = Dependence.objects.filter(cod_father_id=idMachineVirtual)

    if isDependenceFather_Father.count() == 0:
        # Validamos que NO aparezca como hijo
        isDependenceChild_Father = Dependence.objects.filter(cod_child_id=idMachineVirtual)
        if isDependenceChild_Father.count() == 0:
            hostSais = HostSai.objects.filter(host_id=idMachineVirtual)
            for hostSai in hostSais:
                hostSai.delete()

            host = Host.objects.get(id=idMachineVirtual)
            host.delete()


class getAllFathers(APIView):
    """Clase que retorna todos los hosts Padres del usuario en session"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = HostSerializer

    def post(self, request, *args, **kwargs):
        """
        Retorna todos los hosts padres del usuario
        :param request peticion de consulta (idUser)
        """

        userId = request.data['idUser']

        listFathers = []
        allHosts = Host.objects.filter(user_id=userId)

        for host in allHosts:
            # Consultamos si tiene hijos
            withFathers = Dependence.objects.filter(cod_father=host)
            if withFathers.count() > 0:
                # Consultamos si tiene Padres
                withChilds = Dependence.objects.filter(cod_child=host)
                if withChilds.count() == 0:
                    print('Padre = ', host)
                    listFathers.append(host)

        serializer = HostSerializer(listFathers, many=True)

        if listFathers:
            result = {'hosts': serializer.data}
            return Response(result, status=status.HTTP_200_OK)
        else:
            return Response('Without-Machines', status=status.HTTP_200_OK)
