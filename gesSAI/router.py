from rest_framework.routers import SimpleRouter

from django.urls import path

from apps.group.api.resources import GroupViewSet
from apps.host.api.resources import HostViewSet, getHost_ExistMachineView, getHostsByGroup, getMasterHosts, getAllFathers, \
    getHostsOfMasterHost, getAllHostsInAGroup, getHostByName, createDependence, getChildrenFromFather, \
    getParentsFromParent, deleteDependence, getTreeDependence
from apps.pool.api.resources import PoolViewSet, syncPool
from apps.sai.api.resources import SaiViewSet, tryConnectionSAI, getBatterySai
from apps.user.api.resources import UserViewSet, LoginGessai
from apps.virtual_machine.api.resources import VirtualMachineViewSet, getVirtualMachinesView

router = SimpleRouter()
router.register(r'hosts', HostViewSet, basename='Host')
router.register(r'pools', PoolViewSet, basename='Pool')
router.register(r'sais', SaiViewSet, basename='Sai')
router.register(r'users', UserViewSet, basename='User')
router.register(r'virtualmachine', VirtualMachineViewSet, basename='VirtualMachine')
router.register(r'groups', GroupViewSet, basename='Group')

urlpatterns = [
    path('login', LoginGessai.as_view()),
    path('host/exists-machine/', getHost_ExistMachineView.as_view()),
    path('group/hosts/', getHostsByGroup.as_view()),
    path('hosts-master/', getMasterHosts.as_view()),
    path('hosts-pool/', getHostsOfMasterHost.as_view()),
    path('connection-sai/', tryConnectionSAI.as_view()),
    path('machinesInGroup/', getAllHostsInAGroup.as_view()),
    path('existsMachineByNameHost/', getHostByName.as_view()),
    path('createDependence/', createDependence.as_view()),
    path('deleteDependence/', deleteDependence.as_view()),
    path('hosts-children/', getChildrenFromFather.as_view()),
    path('hosts-fathers/', getParentsFromParent.as_view()),
    path('all-host-fathers/', getAllFathers.as_view()),
    path('pool/<int:id_pool>/virtualmachines/', getVirtualMachinesView.as_view()),
    path('sync-pool/', syncPool.as_view()),
    path('treeDependences/', getTreeDependence.as_view()),
    path('battery-sai/', getBatterySai.as_view()),
]

urlpatterns += router.urls
