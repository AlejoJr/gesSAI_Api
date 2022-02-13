from rest_framework.routers import SimpleRouter

from django.urls import path

from apps.group.api.resources import GroupViewSet
from apps.host.api.resources import HostViewSet, getHost_ExistMachineView, getHostsByGroup, getMasterHosts
from apps.pool.api.resources import PoolViewSet
from apps.sai.api.resources import SaiViewSet
from apps.user.api.resources import UserViewSet, LDAPLogin
from apps.virtual_machine.api.resources import VirtualMachineViewSet, getVirtualMachinesView

router = SimpleRouter()
router.register(r'hosts', HostViewSet, basename='Host')
router.register(r'pools', PoolViewSet, basename='Pool')
router.register(r'sais', SaiViewSet, basename='Sai')
router.register(r'users', UserViewSet, basename='User')
router.register(r'virtualmachine', VirtualMachineViewSet, basename='VirtualMachine')
router.register(r'groups', GroupViewSet, basename='Group')

urlpatterns = [
    path('login', LDAPLogin.as_view()),
    path('host/exists-machine/', getHost_ExistMachineView.as_view()),
    path('group/hosts/', getHostsByGroup.as_view()),
    path('hosts-master/', getMasterHosts.as_view()),
    path('pool/<int:id_pool>/virtualmachines/', getVirtualMachinesView.as_view()),
]

urlpatterns += router.urls
