from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import viewsets, status
from rest_framework.views import APIView

from apps.group.api.serializers import GroupSerializer


class GroupViewSet(viewsets.ModelViewSet):
    """Clase que contiene los metodos genericos para la vista de los Groups
    ['get', 'post', 'put', 'delete']"""

    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = GroupSerializer

    def get_queryset(self, pk=None):
        if pk is None:
            return self.get_serializer().Meta.model.objects.filter(
                user_id=self.request.user.pk)
        return self.get_serializer().Meta.model.objects.filter(id=pk).first()

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            newGroup = serializer.save()
            newIdGroup = newGroup.id
            return Response({'message': 'Created-OK','idGroup': newIdGroup}, status=status.HTTP_201_CREATED)
        return Response({'message': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None, *args, **kwargs):
        if self.get_queryset(pk):
            group_serializer = self.serializer_class(self.get_queryset(pk), data=request.data)
            if group_serializer.is_valid():
                group_serializer.save()
                # return Response(host_serializer.data, status=status.HTTP_200_OK)
                return Response("Updated-OK", status=status.HTTP_200_OK)
            return Response(group_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None, *args, **kwargs):
        group = self.get_queryset().filter(id=pk).first()
        if group:
            group.delete()
            return Response({'message': 'Grupo eliminado correctamente!'}, status=status.HTTP_200_OK)
        return Response({'error': 'No existe el Grupo para eliminarlo'}, status=status.HTTP_400_BAD_REQUEST)