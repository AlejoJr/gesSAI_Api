from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import viewsets, status

from apps.sai.api.serializers import SaiSerializer


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
            serializer.save()
            return Response({'message': 'Sai creado correctamente!'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None, *args, **kwargs):
        if self.get_queryset(pk):
            sai_serializer = self.serializer_class(self.get_queryset(pk), data=request.data)
            if sai_serializer.is_valid():
                sai_serializer.save()
                return Response(sai_serializer.data, status=status.HTTP_200_OK)
            return Response(sai_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None, *args, **kwargs):
        sai = self.get_queryset().filter(id=pk).first()
        if sai:
            sai.delete()
            return Response({'message': 'Sai eliminado correctamente!'}, status=status.HTTP_200_OK)
        return Response({'error': 'No existe el Sai para eliminarlo'}, status=status.HTTP_400_BAD_REQUEST)
