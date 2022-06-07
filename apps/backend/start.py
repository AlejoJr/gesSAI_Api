from pysnmp.hlapi import *
# from apps.sai.models import Sai
# from apps.pool.models import Pool
import time

"""CONFIGURACION PARA DEBUG"""
import os

if not os.environ.get('DJANGO_SETTINGS_MODULE'):
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "gesSAI.settings")

# El segundo error es realizar las siguientes configuraciones y actualizar el archivo de configuración;
import django

django.setup()

from apps.sai.models import Sai
from apps.pool.models import Pool
from apps.group.models import Dependence

import cryptocode
import threading
import subprocess

if __name__ == '__main__':  # <--- esto permite ejecutar el archivo
    print("Inicio")

"""FIN CONFIGURACION"""

CODE_LEVEL_BATTERY = 'SNMPv2-SMI::mib-2.33.1.2.4.0'
BATTERY_VOLTAGE = 'SNMPv2-SMI::mib-2.33.1.2.5.0'


def crear_hilos_MF(sai):
    # Obtenemos todas las maquinas fisicas que pertenecen al SAI y NO estan en ningun grupo
    # machinesPhysical = Host.objects.filter(sais=sai, group=None)
    #Obtengo solo los hijos, (Hijos que no son padres)
    hijos = Dependence.objects.filter(cod_child__sais=sai).filter(cod_child__host_father__cod_child__isnull=True)

    hilosHijos = []
    for hijo in hijos:
        print('---soloHijos----')
        print('Hijo :' + hijo.cod_child.name_host)
        print('Padre :' + hijo.cod_father.name_host)
        #hilo = threading.Thread(target=apagar_hijo_MF, args=(hijo, machine.so,))
        #hilosHijos.append(hilo)

    # Ejecutamos los hilos
    for hiloHijo in hilosHijos:
        hiloHijo.start()



def apagar_hijo_MF(nameMachine, so):
    if so == 'L':
        print('apagamos linux ' + nameMachine)
        subprocess.check_output(['ssh', 'root@' + nameMachine + '.dsic.upv.es', 'shutdown now'])
    elif so == 'W':
        print('apagamos windows ' + nameMachine)
        subprocess.check_output(['ssh', 'root@' + nameMachine + '.dsic.upv.es', 'shutdown /p'])
    else:
        print('apagamos mac ' + nameMachine)



def sai():
    level = ''
    print('<-- Inicia metodo -->')
    sais = Sai.objects.filter(type=1, state='Free')
    for sai in sais:
        print('SAI: ' + sai.name_sai)
        url_sai = sai.url.replace('http://', '').replace('https://', '')

        level = batteryLevel(url_sai, sai.code_oid)

        if level == 100:
            sai.state = 'Busy'
            sai.save()
            pools = Pool.objects.filter(ip='10.10.10.8')
            pool = pools[0]
            result = pool.session.xenapi.network.get_all_records()
            print(result)

    if level == '':
        pass


def batteryLevel(host, oid):
    level = ''
    iterator = getCmd(
        SnmpEngine(),
        UsmUserData('root', authKey='T3cn1c0s', privKey='T3cn1c0s'),
        UdpTransportTarget((host, 161)),
        ContextData(),
        # ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
        ObjectType(ObjectIdentity(oid))
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:
        print(errorIndication)

    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))

    else:
        for varBind in varBinds:
            code = str(varBind[0].prettyPrint())
            if CODE_LEVEL_BATTERY == code:
                level = int(varBind[1])
                print('Nivel de batería: ' + str(level) + '%')
            # print(' = '.join([x.prettyPrint() for x in varBind]))

    return level


# sai()
sais = Sai.objects.filter(state='Free')
for sai in sais:
    crear_hilos_MF(sai)
