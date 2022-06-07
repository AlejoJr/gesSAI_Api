from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import viewsets, status
from rest_framework.views import APIView

from apps.backend.utils import get_env_setting
from apps.host.models import Host, HostSai
from apps.pool.api.serializers import PoolSerializer

from apps.backend.hipervisor_api.xenapi import conection
from apps.pool.models import Pool
from apps.sai.models import Sai

import cryptocode


class PoolViewSet(viewsets.ModelViewSet):
    """Clase que contiene los metodos genericos para la vista de los Pools
    ['get', 'post', 'put', 'delete']"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = PoolSerializer

    def get_queryset(self, pk=None):
        if pk is None:
            return self.get_serializer().Meta.model.objects.filter(
                user_id=self.request.user.pk)  # -->Filtro los Pools por el usuario que esta en session
        return self.get_serializer().Meta.model.objects.filter(id=pk).first()

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            pool = Pool.objects.filter(ip=serializer.initial_data['ip']).filter(
                url=serializer.initial_data['url']).exists()

            if pool:
                return Response("Im Used", status=status.HTTP_226_IM_USED)
            else:
                try:
                    namePool = request.data['name_pool']
                    url = request.data['url']
                    username = request.data['username']
                    password = request.data['password']
                    typeHipervisor = request.data['type']
                    user = request.data['user']
                    sais = request.data['sais']

                    isConnected = conection(url=url, user=username, hipervisor_type=typeHipervisor, password=password)

                    if isConnected:
                        semilla = get_env_setting('SEMILLA')

                        #Cifrar contraseña
                        password_encoded = cryptocode.encrypt(password, semilla)

                        idNewPool = ''
                        pool = isConnected.xenapi.pool.get_all()[0]

                        # <-- H O S T - M A S T E R -->>
                        hostMaster = isConnected.xenapi.pool.get_master(pool)
                        nameHostMaster = isConnected.xenapi.host.get_name_label(hostMaster)
                        pifsHostmaster = isConnected.xenapi.host.get_PIFs(hostMaster)

                        for refPif in pifsHostmaster:
                            recordPif = isConnected.xenapi.PIF.get_record(refPif)
                            if recordPif['management'] == True:
                                objPool = Pool(name_pool=namePool,
                                               ip=recordPif['IP'],
                                               url=url,
                                               username=username,
                                               password=password_encoded,
                                               type=typeHipervisor,
                                               user_id=user)

                                objPool.save()
                                idNewPool = objPool.id

                                # Agregamos la relacion muchos a muchos (los sais al pool)
                                for idSai in sais:
                                    sai = Sai.objects.get(id=idSai)
                                    objPool.sais.add(sai)

                                # Alta Host Master
                                objHostMaster = Host(name_host=nameHostMaster,
                                                     ip=recordPif['IP'],
                                                     mac=recordPif['MAC'],
                                                     type_host='HM',
                                                     pool_id=objPool.id,
                                                     user_id=user)
                                objHostMaster.save()

                                # Agregamos la relacion muchos a muchos (los sais al host)
                                for idSai in sais:
                                    sai = Sai.objects.get(id=idSai)
                                    m1 = HostSai(host=objHostMaster, sai=sai, enchufado=True)
                                    m1.save()

                        # <-- O T R O S - H O S T S -->>
                        hosts = isConnected.xenapi.host.get_all()
                        for refHost in hosts:
                            if refHost != hostMaster:
                                nameHost = isConnected.xenapi.host.get_name_label(refHost)
                                pifsHost = isConnected.xenapi.host.get_PIFs(refHost)

                                for refPif in pifsHost:
                                    recordPif = isConnected.xenapi.PIF.get_record(refPif)
                                    if recordPif['management'] == True:
                                        objHost = Host(name_host=nameHost,
                                                       ip=recordPif['IP'],
                                                       mac=recordPif['MAC'],
                                                       type_host='HO',
                                                       pool_id=idNewPool,
                                                       user_id=user)
                                        objHost.save()

                        return Response('Created-OK', status=status.HTTP_201_CREATED)
                    else:
                        return Response("No-Connected", status=status.HTTP_204_NO_CONTENT)
                except Exception:
                    return Response("No-Connected", status=status.HTTP_204_NO_CONTENT)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None, *args, **kwargs):
        if self.get_queryset(pk):
            pool_serializer = self.serializer_class(self.get_queryset(pk), data=request.data)
            if pool_serializer.is_valid():
                pool_serializer.save()

                # return Response(pool_serializer.data, status=status.HTTP_200_OK)
                return Response('Updated-OK', status=status.HTTP_200_OK)
            return Response(pool_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None, *args, **kwargs):
        pool = self.get_queryset().filter(id=pk).first()
        if pool:
            pool.delete()
            return Response({'message': 'Pool eliminado correctamente!'}, status=status.HTTP_200_OK)
        return Response({'error': 'No existe el Pool para eliminarlo'}, status=status.HTTP_400_BAD_REQUEST)


class syncPool(APIView):
    """Clase que sincroniza los hosts del Pool"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = PoolSerializer

    def post(self, request, *args, **kwargs):
        """
        Retorna Ok si la sincronización es correcta
        :param request peticion de consulta (pool)
        """

        try:
            idPool = request.data['id']
            url = request.data['url']
            username = request.data['username']
            password = request.data['password']
            typeHipervisor = request.data['type']
            user = request.data['user']

            #Desencriptamos la clave
            semilla = get_env_setting('SEMILLA')
            password_decoded = cryptocode.decrypt(password, semilla)

            isConnected = conection(url=url, user=username, hipervisor_type=typeHipervisor, password=password_decoded)

            if isConnected:
                # Eliminamos todos los Hosts del Pool
                hostOfPool = Host.objects.filter(pool_id=idPool).filter(type_host='HO')
                for objHost in hostOfPool:
                    objHost.delete()

                # Creamos nuevamente los hosts del Pool
                pool = isConnected.xenapi.pool.get_all()[0]
                hostMaster = isConnected.xenapi.pool.get_master(pool)  # <-- Host master

                hosts = isConnected.xenapi.host.get_all()
                for refHost in hosts:
                    if refHost != hostMaster:
                        nameHost = isConnected.xenapi.host.get_name_label(refHost)
                        pifsHost = isConnected.xenapi.host.get_PIFs(refHost)

                        for refPif in pifsHost:
                            recordPif = isConnected.xenapi.PIF.get_record(refPif)
                            if recordPif['management'] == True:
                                objHost = Host(name_host=nameHost,
                                               ip=recordPif['IP'],
                                               mac=recordPif['MAC'],
                                               type_host='HO',
                                               pool_id=idPool,
                                               user_id=user)
                                objHost.save()

                return Response('Sync-OK', status=status.HTTP_201_CREATED)
            else:
                return Response("No-Connected", status=status.HTTP_204_NO_CONTENT)
        except Exception:
            return Response("No-Connected", status=status.HTTP_204_NO_CONTENT)
