from django.core.management.base import BaseCommand
from pysnmp.hlapi import *
from django.db.models import Q

import cryptocode
import threading
import subprocess
import platform
import time
import paramiko
from paramiko.ssh_exception import AuthenticationException

from apps.backend.hipervisor_api import virtual_machines
from apps.backend.hipervisor_api.xenapi import conection
from apps.backend.utils import get_env_setting
from apps.sai.models import Sai
from apps.host.models import Dependence, Host, HostSai
from apps.pool.models import Pool


class Command(BaseCommand):
    def handle(self, **options):
        try:
            level = ''
            sais = Sai.objects.filter(state='not started')
            for sai in sais:
                print('\n<<|-----------| ', 'SAI: ' + sai.name_sai, ' |-----------------|>>')
                url_sai = sai.url.replace('http://', '').replace('https://', '')
                user_sai = sai.userConnection
                authKey_sai = sai.authKey
                privKey_sai = sai.privKey
                valueOff = sai.value_off

                # Desencriptamos las claves
                print('Desencriptando claves')
                semilla = get_env_setting('SEMILLA')
                authKey_decoded = cryptocode.decrypt(authKey_sai, semilla)
                privKey_decoded = cryptocode.decrypt(privKey_sai, semilla)

                print('Obteniendo: Duración restante de la batería')
                level = batteryLevel(user_sai, authKey_decoded, privKey_decoded, url_sai, sai.code_oid)

                if level <= int(valueOff):
                    print('\n      <<- Inicia proceso de Apagado ->>')
                    finished_child = Dependence.objects.update(finished_child=0)  # Inicializamos todos a 0
                    apagarMaquinasDependientes(sai)
                    apagarMaquinasNoDependientes(sai)
                    sai.state = 'started'
                    sai.save()
                else:
                    print('SAI configurado para iniciar apagado a los (', valueOff, ' Minutos)')
                    print('Aun queda batería suficiente.')

            if level == '':
                print('El SAI esta en estado (started) o No existe ningun SAI')
                pass
        except Exception as e:
            print('Error Iniciando el Script: ', e)


def apagarMaquinasNoDependientes(sai):
    # <-- M A Q U I N A S - F I S I C A S -->
    hostSai = HostSai.objects.filter(sai_id=sai.id, enchufado=True)  # Filtrar solo maquinas enchufadas al SAI
    hostsMF = Host.objects.filter(type_host='MF').filter(hostsai__in=hostSai)  # Filtrar solo (MF) pertenecientes al SAI

    # Filtrar las dependencias donde solo aparecen las (MF)
    dependencesMF = Dependence.objects.filter(cod_father__in=hostsMF) | Dependence.objects.filter(cod_child__in=hostsMF)
    # Filtrar solo (MF) que NO tienen ninguna Dependencia
    hostsMF_off = hostsMF.exclude(Q(host_father__in=dependencesMF) | Q(host_child__in=dependencesMF))

    print('\n<-- Apagando Maquinas Fisicas sin Dependencia -->')
    for mf in hostsMF_off:
        client = paramiko.SSHClient()
        # id_rsa es el archivo de clave privada del servidor
        private_key = paramiko.RSAKey.from_private_key_file('/Users/alejojr/.ssh/id_rsa')

        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        print('   Máquina -:', mf, '  SO -:', mf.so)

        cmd = 'shutdown now'
        cmd = 'shutdown /p' if mf.so == 'W' else cmd

        try:
            client.connect(hostname=mf.name_host,
                           port=22,
                           username='root',
                           pkey=private_key,
                           timeout=2)

            stdin, stdout, stderr = client.exec_command(cmd)
        except AuthenticationException as e:
            print("Contraseña Incorrecta")
        except Exception as e:
            print('Exception: Error Apagando la Máquina')
        else:
            result = stdout.read().decode('utf-8')
            print('   MF -:', mf.name_host, '  Status -:', 'Apagada ', result)

        finally:
            client.close()

    # <-- M A Q U I N A S - V I R T U A L E S -->
    print('\n<-- Apagando Maquinas Virtuales sin Dependencia -->')
    pools = Pool.objects.filter(sais=sai)
    for pool in pools:
        print('   Pool: ', pool)
        virtualMachines = virtual_machines.VirtualMachines.listOfMachinesOn(pool)
        for vm in virtualMachines:
            bdMV = Host.objects.filter(name_host=vm['name_host']).exists()
            if bdMV == False:
                # Desencriptamos la clave Y Abrimos session con xen
                semilla = get_env_setting('SEMILLA')
                password_decoded = cryptocode.decrypt(pool.password, semilla)
                session = conection(url=pool.url, user=pool.username, hipervisor_type=pool.type,
                                    password=password_decoded)
                responseVM = virtual_machines.VirtualMachines.hard_shutdown_vm(session, vm['id'])
                print('   VM -:', vm['name_host'], '  Status -:', responseVM)


def apagarMaquinasDependientes(sai):
    print('\n<-- Apagando Maquinas Con Dependencia -->')
    allHostFathers = Dependence.objects.values('cod_father').distinct()

    hostLeafs = Dependence.objects.exclude(
        Q(cod_child__in=allHostFathers))  # Obtenemos todas las Hojas (Hijos sin Hijos)

    childs = hostLeafs.values('cod_child').distinct()  # Quitamos los Hosts repetidos
    hosts = Host.objects.filter(id__in=childs)
    apagarMaquina(sai, hosts)


def apagarMaquina(sai, hosts):
    hilos = []
    # Por cada Host creamos un hilo, para posteriormente apagarlo.
    count = 0
    try:
        for host in hosts:
            count = count + 1
            print('Hilo: ', count, ' Host a apagar ->', host.name_host)
            hilo = threading.Thread(target=hostShutdown, args=(sai, host))
            hilos.append(hilo)

        # Ejecutamos los hilos
        for hilo in hilos:
            hilo.start()
    except Exception as e:
        print('Exception lanzando hilos (Metodo: apagarMaquina()): ', e)


def hostShutdown(sai, host):
    # 1). Estoy relacionado al SAI ?
    for sai_host in host.sais.all():
        if sai_host == sai:
            childsForShutdown = Dependence.objects.filter(cod_father=host, finished_child=0)
            if childsForShutdown:
                print('Padre: ', host.name_host, ' -No se han apagado todos sus Hijos')
            else:
                try:
                    # <-- M A Q U I N A S - F I S I C A S -->
                    if host.type_host == 'MF' or host.type_host == 'SM':
                        client = paramiko.SSHClient()
                        # id_rsa es el archivo de clave privada del servidor
                        private_key = paramiko.RSAKey.from_private_key_file('/Users/alejojr/.ssh/id_rsa')

                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                        print('   Máquina -:', host.name_host, '  SO -:', host.so, ' Tipo -: ', host.type_host)

                        cmd = 'shutdown now'
                        cmd = 'shutdown /p' if host.so == 'W' else cmd

                        try:
                            client.connect(hostname=host.name_host,
                                           port=22,
                                           username='root',
                                           pkey=private_key,
                                           timeout=2)

                            stdin, stdout, stderr = client.exec_command(cmd)
                        except AuthenticationException as e:
                            print("Contraseña Incorrecta")
                        except Exception as e:
                            print('Exception: Error Apagando la Máquina')
                            # De todos modos Actualizamos la BD para continuar el apagado de los padres, ha apagado = 1
                            Dependence.objects.filter(cod_child=host).update(finished_child=1)
                        else:
                            result = stdout.read().decode('utf-8')
                            print(host.type_host, '  -:', host.name_host, '  Status -:', 'Apagada ', result)
                            responsePing, responseTime = comprobarMaquinaApagada(host=host.name_host, pool=None,
                                                                                 poolSession=None,
                                                                                 varAux=None)

                            # Actualizamos la BD ha apagado = 1
                            Dependence.objects.filter(cod_child=host).update(finished_child=1)

                            # Obtenemos los Padres y enviamos señal ha apagar
                            myFathers = Dependence.objects.filter(cod_child=host)
                            listHosts = []
                            for father in myFathers:
                                listHosts.append(father.cod_father)

                            print('Hijo: ', host.name_host, ' -> Padres: ', listHosts)
                            apagarMaquina(sai, listHosts)
                        finally:
                            client.close()
                    else:
                        # <-- M A Q U I N A S - V I R T U A L E S -->
                        pool = host.pool
                        if pool is not None:
                            # Desencriptamos la clave Y Abrimos session con xen
                            semilla = get_env_setting('SEMILLA')
                            password_decoded = cryptocode.decrypt(pool.password, semilla)
                            session = conection(url=pool.url, user=pool.username, hipervisor_type=pool.type,
                                                password=password_decoded)

                            if host.type_host == 'HM':
                                # <-- H O S T - M A S T E R -->>
                                pool = session.xenapi.pool.get_all()[0]
                                hostMaster = session.xenapi.pool.get_master(pool)  # -> Ref hostMaster
                                # <-- O T R O S - H O S T S -->>
                                hosts = session.xenapi.host.get_all()
                                for refHost in hosts:
                                    if refHost != hostMaster:
                                        disabled_host = session.xenapi.host.disable(refHost)  # Desabilitamos el Host
                                        shutdown_host = session.xenapi.host.shutdown(refHost)  # Apagamos el Host

                                disabled_host = session.xenapi.host.disable(hostMaster)  # Desabilitamos el HostMaster
                                shutdown_host = session.xenapi.host.shutdown(hostMaster)  # Apagamos el HostMaster

                                responsePing, responseTime = comprobarMaquinaApagada(host=host, pool=pool,
                                                                                     poolSession=None,
                                                                                     varAux=password_decoded)
                            else:
                                refNameHost = session.xenapi.VM.get_by_name_label(host.name_host)
                                uuid = session.xenapi.VM.get_uuid(refNameHost[0])
                                responseVM = virtual_machines.VirtualMachines.hard_shutdown_vm(session, uuid)

                                responsePing, responseTime = comprobarMaquinaApagada(host=host, pool=pool,
                                                                                     poolSession=session,
                                                                                     varAux=uuid)

                            # Actualizamos la BD ha apagado = 1
                            Dependence.objects.filter(cod_child=host).update(finished_child=1)

                            # Obtenemos los Padres y enviamos señal ha apagar
                            myFathers = Dependence.objects.filter(cod_child=host)
                            listHosts = []
                            for father in myFathers:
                                listHosts.append(father.cod_father)

                            print('Hijo: ', host.name_host, ' -> Padres: ', listHosts)
                            apagarMaquina(sai, listHosts)
                except Exception as e:
                    print('Exception Apagando Maquina (Metodo: hostShutdown()): ', e)


def comprobarMaquinaApagada(host, pool=None, poolSession=None, varAux=None):
    responsePing = True
    responseTime = False

    try:
        if pool is None:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout = time.time() + 30  # 30 segundos de espera
            while True:
                # Building the command
                command = ['ping', param, '1', host]

                responsePing = subprocess.call(command) == 0
                responseTime = time.time() > timeout
                aux = 0
                if responsePing == False or responseTime:
                    print('MF: ', host, ' - Ping: ', responsePing, ' - TimeOut: ', responseTime)
                    break
                aux = aux - 1
        else:
            timeout = time.time() + 30  # 30 segundos de espera
            if host.type_host == 'HM':
                time.sleep(10)
                try:
                    while True:
                        session = conection(url=pool.url, user=pool.username, hipervisor_type=pool.type,
                                            password=varAux)

                        responseTime = time.time() > timeout
                        aux = 0
                        if responseTime:
                            print('TimeOut: ', responseTime)
                            break
                        aux = aux - 1

                except Exception as e:
                    print('Host-Master No Responde - Estado: Apagado')
                    responsePing = False
            else:
                while True:
                    refVM = poolSession.xenapi.VM.get_by_uuid(varAux)
                    powerState = poolSession.xenapi.VM.get_power_state(refVM)

                    responsePing = False if powerState == 'Halted' else True
                    responseTime = time.time() > timeout
                    aux = 0
                    if responsePing == False or responseTime:
                        print('MV: ', host, ' - Status: ', powerState, ' - TimeOut: ', responseTime)
                        break
                    aux = aux - 1

        return (responsePing, responseTime)

    except Exception as e:
        print('Exception Comprobando Maquina Apagada (Metodo: comprobarMaquinaApagada()): ', e)


def batteryLevel(user, authKey_sai, priveKey_sai, host, oid):
    level = ''
    iterator = getCmd(
        SnmpEngine(),
        UsmUserData(user, authKey=authKey_sai, privKey=priveKey_sai),
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
            level = int(varBind[1])
            print('Tiempo restante de batería: ' + str(level) + ' Minutos')
            print('Codigo de MIB: ' + str(code))
            """if CODE_LEVEL_BATTERY == code:
                level = int(varBind[1])
                print('Nivel de batería: '+str(level)+'%')"""
            # print(' = '.join([x.prettyPrint() for x in varBind]))

    return level