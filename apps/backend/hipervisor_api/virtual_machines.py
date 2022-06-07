import json


class VirtualMachines(object):
    """Clase que utiliza xenapi para
        operar las maquinas virtuales"""

    def list(pool):
        """Lista todas las maquinas virtuales del Pool"""

        virtual_machines = []

        try:
            # Hipervisor XEN
            if pool.type == 'X':
                records = pool.session.xenapi.VM.get_all_records_where('field "is_a_template" = "false" and '
                                                                       'field "is_a_snapshot" = "false" and '
                                                                       'field "is_control_domain" = "false"')

                for ref in records:
                    data = {}
                    virtual_machine = {}
                    vm = records[ref]
                    vm['ref'] = ref

                    data['value'] = vm['uuid']
                    data['label'] = vm['name_label']
                    data['name_host'] = vm['name_label']
                    data['ref'] = vm['ref']
                    data['id'] = vm['uuid']
                    data['power_state'] = vm['power_state']
                    data['pool_id'] = pool.id
                    data['pool_name'] = pool.name_pool
                    data['type_host'] = 'MV'

                    # virtual_machine[data['name']] = data

                    virtual_machines.append(data)
        except:
            return "Error get vms"

        return virtual_machines

    def listOfMachinesOn(pool):
        """Lista las Maquinas virtuales que estan encendidas (Running)"""
        virtual_machines = []

        try:
            # Hipervisor XEN
            if pool.type == 'X':
                records = pool.session.xenapi.VM.get_all_records_where('field "power_state" = "Running" and '
                                                                       'field "is_control_domain" = "false"')

                for ref in records:
                    data = {}
                    vm = records[ref]
                    #print('referencia  vm: ', vm)
                    vm['ref'] = ref

                    data['id'] = vm['uuid']
                    data['name_host'] = vm['name_label']
                    data['ref'] = vm['ref']
                    data['power_state'] = vm['power_state']

                    virtual_machines.append(data)

        except:
            return "Error get list of machines on"

        return virtual_machines

    def hard_shutdown_vm(session, uuid):
        """Apaga una Maquina virtual con un Hard Shutdown pasandole el Uuid de la VM"""
        #vm = pool.session.xenapi.VM.get_by_uuid(uuid)
        vm = session.xenapi.VM.get_by_uuid(uuid)
        try:
            #pool.session.xenapi.VM.hard_shutdown(vm)
            session.xenapi.VM.hard_shutdown(vm)
            return "halted"
        except Exception as e:
            print('Error apagando la VM -: ', e)
            if not hasattr(e, 'details'):
                return 'Sin detalles'
            if e.details[0] == 'VM_BAD_POWER_STATE':
                return 'VM_BAD_POWER_STATE'
            if e.details[0] == 'NO_HOSTS_AVAILABLE':
                return 'VM_BAD_POWER_STATE'
            if e.details[0] == 'VM_LACKS_FEATURE_SHUTDOWN':
                return 'VM_LACKS_FEATURE_SHUTDOWN'
            return None

    def start_vm(session, uuid):
        """Enciende una Maquina virtual con un Start pasandole el Uuid de la VM"""
        vm = session.xenapi.VM.get_by_uuid(uuid)
        try:
            session.xenapi.VM.start(vm, False, True)
            return "Running"
        except Exception as e:
            print('Error encendiendo la VM -: ', e)
            if not hasattr(e, 'details'):
                return 'Sin detalles'
            if e.details[0] == 'VM_BAD_POWER_STATE':
                return "Running"
            if e.details[0] == 'NO_HOSTS_AVAILABLE':
                return 'NO_HOSTS_AVAILABLE'
            if e.details[0] == 'VM_LACKS_FEATURE_SHUTDOWN':
                return 'VM_LACKS_FEATURE_SHUTDOWN'
            return None
