from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import viewsets, status

from apps.pool.api.serializers import PoolSerializer


class PoolViewSet(viewsets.ModelViewSet):
    """Clase que contiene los metodos genericos para la vista de los Pools
    ['get', 'post', 'put', 'delete']"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = PoolSerializer

    def get_queryset(self, pk=None):
        if pk is None:
            return self.get_serializer().Meta.model.objects.all()
        return self.get_serializer().Meta.model.objects.filter(id=pk).first()

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            #return Response({'message': 'Pool creado correctamente!'}, status=status.HTTP_201_CREATED)
            return Response('Created-OK', status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None, *args, **kwargs):
        if self.get_queryset(pk):
            pool_serializer = self.serializer_class(self.get_queryset(pk), data=request.data)
            if pool_serializer.is_valid():
                pool_serializer.save()
                #return Response(pool_serializer.data, status=status.HTTP_200_OK)
                return Response('Updated-OK', status=status.HTTP_200_OK)
            return Response(pool_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None, *args, **kwargs):
        pool = self.get_queryset().filter(id=pk).first()
        if pool:
            pool.delete()
            return Response({'message': 'Pool eliminado correctamente!'}, status=status.HTTP_200_OK)
        return Response({'error': 'No existe el Pool para eliminarlo'}, status=status.HTTP_400_BAD_REQUEST)
