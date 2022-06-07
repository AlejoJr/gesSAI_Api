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
from wakeonlan import send_magic_packet


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
            sais = Sai.objects.filter(state='started')
            for sai in sais:
                print('\n<<|-----------| ', 'SAI: ' + sai.name_sai, ' |-----------------|>>')
                url_sai = sai.url.replace('http://', '').replace('https://', '')
                user_sai = sai.userConnection
                authKey_sai = sai.authKey
                privKey_sai = sai.privKey
                valueOn = sai.value_on

                # Desencriptamos las claves
                print('Desencriptando claves')
                semilla = get_env_setting('SEMILLA')
                authKey_decoded = cryptocode.decrypt(authKey_sai, semilla)
                privKey_decoded = cryptocode.decrypt(privKey_sai, semilla)

                print('Obteniendo: Duración restante de la batería')
                level = batteryLevel(user_sai, authKey_decoded, privKey_decoded, url_sai, sai.code_oid)

                if level > int(valueOn):
                    print('\n      <<- Inicia proceso de Encendido ->>')
                    finished_father = Dependence.objects.update(finished_father=0)  # Inicializamos todos a 1
                    encenderMaquinasDependientes(sai)
                    encenderMaquinasNoDependientes(sai)
                    #sai.state = 'not started'
                    #sai.save()
                else:
                    print('SAI configurado para iniciar Encendido a los (', valueOn, ' Minutos)')
                    print('Aun falta que recargue la batería del SAI.')

            if level == '':
                print('El SAI esta en estado (not started) o No existe ningun SAI')
                pass
        except Exception as e:
            print('Error Iniciando el Script: ', e)


def encenderMaquinasNoDependientes(sai):
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


def encenderMaquinasDependientes(sai):
    print('\n<-- Encendiendo Maquinas Con Dependencia -->')
    allHostChilds = Dependence.objects.values('cod_child').distinct()

    hostFathers = Dependence.objects.exclude(
        Q(cod_father__in=allHostChilds))  # Obtenemos todas los Padres (Padres sin Padres)

    fathers = hostFathers.values('cod_father').distinct()  # Quitamos los Hosts repetidos
    hosts = Host.objects.filter(id__in=fathers)
    encenderMaquina(sai, hosts)


def encenderMaquina(sai, hosts):
    hilos = []
    # Por cada Host creamos un hilo, para posteriormente encenderlo.
    count = 0
    try:
        for host in hosts:
            count = count + 1
            print('Hilo: ', count, ' Host a encender ->', host.name_host)
            hilo = threading.Thread(target=hostStart, args=(sai, host))
            hilos.append(hilo)

        # Ejecutamos los hilos
        for hilo in hilos:
            hilo.start()
    except Exception as e:
        print('Exception lanzando hilos (Metodo: encenderMaquina()): ', e)


def hostStart(sai, host):
    # 1). Estoy relacionado al SAI ?
    for sai_host in host.sais.all():
        if sai_host == sai:
            fathersForShutdown = Dependence.objects.filter(cod_child=host, finished_father=0)
            if fathersForShutdown:
                print('Hijo: ', host.name_host, ' -No se han encendido todos sus Padres')
            else:
                try:
                    # <-- M A Q U I N A S - F I S I C A S -->
                    if host.type_host == 'MF' or host.type_host == 'SM':
                        try:
                            send_magic_packet(host.mac) # Enviamos paquete magico para encender el host, (Wake On Lan)
                        except Exception as e:
                            print('Exception: Error enviando Wake On Lan')
                            # De todos modos Actualizamos la BD para continuar el encendido de los hijos, ha encendido = 1
                            Dependence.objects.filter(cod_father=host).update(finished_father=1)
                        else:
                            responsePing, responseTime = comprobarMaquinaEncendida(host=host.name_host, pool=None,
                                                                                 poolSession=None,
                                                                                 varAux=None)
                            print(host.type_host, '  -:', host.name_host, '  Status - Encendida: ', responsePing)

                            # Actualizamos la BD ha encendido = 1
                            Dependence.objects.filter(cod_father=host).update(finished_father=1)

                            # Obtenemos los Hijos y enviamos señal ha encender
                            myChilds = Dependence.objects.filter(cod_father=host)
                            listHosts = []
                            for child in myChilds:
                                listHosts.append(child.cod_child)

                            print('Padre: ', host.name_host, ' -> Hijos: ', listHosts)
                            encenderMaquina(sai, listHosts)
                        finally:
                            print(host.name_host, ' Encendido Finalizado')
                    else:
                        # <-- M A Q U I N A S - V I R T U A L E S -->
                        pool = host.pool
                        if pool is not None:
                            if host.type_host == 'HM':
                                # <-- H O S T - M A S T E R -->>
                                send_magic_packet(host.mac)# Enviamos paquete magico para encender el host, (Wake On Lan)

                                responsePing, responseTime = comprobarMaquinaEncendida(host=host, pool=pool,
                                                                                       poolSession=None,
                                                                                       varAux=None)
                                if responsePing:
                                    # Desencriptamos la clave Y Abrimos session con xen
                                    semilla = get_env_setting('SEMILLA')
                                    password_decoded = cryptocode.decrypt(pool.password, semilla)
                                    session = conection(url=pool.url, user=pool.username, hipervisor_type=pool.type,
                                                        password=password_decoded)


                                    pool = session.xenapi.pool.get_all()[0]
                                    hostMaster = session.xenapi.pool.get_master(pool)  # -> Ref hostMaster
                                    # <-- O T R O S - H O S T S -->>
                                    hosts = session.xenapi.host.get_all()
                                    for refHost in hosts:
                                        if refHost != hostMaster:
                                            power_host = session.xenapi.host.power_on(refHost)  # Encendemos el Host

                            else:
                                # Desencriptamos la clave Y Abrimos session con xen
                                semilla = get_env_setting('SEMILLA')
                                password_decoded = cryptocode.decrypt(pool.password, semilla)
                                session = conection(url=pool.url, user=pool.username, hipervisor_type=pool.type,
                                                    password=password_decoded)

                                refNameHost = session.xenapi.VM.get_by_name_label(host.name_host)
                                uuid = session.xenapi.VM.get_uuid(refNameHost[0])
                                responseVM = virtual_machines.VirtualMachines.start_vm(session, uuid)



                            # Actualizamos la BD ha encendido = 1
                            Dependence.objects.filter(cod_father=host).update(finished_father=1)

                            # Obtenemos los Hijos y enviamos señal ha encender
                            myChilds = Dependence.objects.filter(cod_father=host)
                            listHosts = []
                            for child in myChilds:
                                listHosts.append(child.cod_child)

                            print('Padre: ', host.name_host, ' -> Hijos: ', listHosts)
                            encenderMaquina(sai, listHosts)
                except Exception as e:
                    print('Exception Encendiendo Maquina (Metodo: hostStart()): ', e)


def comprobarMaquinaEncendida(host, pool=None, poolSession=None, varAux=None):
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
                if responsePing == True or responseTime:
                    print('MF: ', host, ' - Ping: ', responsePing, ' - TimeOut: ', responseTime)
                    break
                aux = aux - 1
        else:
            timeout = time.time() + 30  # 30 segundos de espera
            if host.type_host == 'HM':
                time.sleep(10)

                while True:
                    try:
                        session = conection(url=pool.url, user=pool.username, hipervisor_type=pool.type, password=varAux)
                        print('Host-Master: ', pool.name_pool, 'Session: ', session)
                        responsePing = True
                        responseTime = time.time() > timeout
                        aux = 0
                        if responseTime or session:
                            print('TimeOut: ', responseTime)
                            break
                        aux = aux - 1
                    except Exception as e:
                        print('Conectando a Host Master ....')
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
        print('Exception Comprobando Maquina Encendida (Metodo: comprobarMaquinaEncendida()): ', e)


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