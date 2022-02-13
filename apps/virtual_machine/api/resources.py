from django.shortcuts import get_object_or_404

from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import viewsets, status
from rest_framework.views import APIView

from apps.pool.models import Pool

from apps.virtual_machine.api.serializers import VirtualMachineSerializer

from apps.backend.hipervisor_api import virtual_machines


class VirtualMachineViewSet(viewsets.ModelViewSet):
    """Clase que contiene los metodos genericos para la vista de las Virtual Machine
    ['get', 'post', 'put', 'delete']"""

    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = VirtualMachineSerializer

    def get_queryset(self, pk=None):
        if pk is None:
            return self.get_serializer().Meta.model.objects.all()
        return self.get_serializer().Meta.model.objects.filter(id=pk).first()

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Virtual Machine - Alta: OK!'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None, *args, **kwargs):
        if self.get_queryset(pk):
            virtual_machine_serializer = self.serializer_class(self.get_queryset(pk), data=request.data)
            if virtual_machine_serializer.is_valid():
                virtual_machine_serializer.save()
                return Response(virtual_machine_serializer.data, status=status.HTTP_200_OK)
            return Response(virtual_machine_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None, *args, **kwargs):
        virtual_machine = self.get_queryset().filter(id=pk).first()
        if virtual_machine:
            virtual_machine.delete()
            return Response({'message': 'Virtual Machine - Baja: OK!'}, status=status.HTTP_200_OK)
        return Response({'error': 'No existe la Virtual Machine para eliminarla'}, status=status.HTTP_400_BAD_REQUEST)


class getVirtualMachinesView(APIView):

    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = VirtualMachineSerializer
    def get(self, request, *args, **kwargs):
        """ Obtiene todas las maquinas virtuales de un pool
            :param id_pool
            :return HTTPResponse con la lista de maquinas virtuales
        """
        id_pool = kwargs.get('id_pool')
        pool = get_object_or_404(Pool, id=id_pool)
        #hosts = pool.host.values()

        virtualMachines = virtual_machines.VirtualMachines.list(pool)

        return Response({'count': len(virtualMachines),'results': virtualMachines})