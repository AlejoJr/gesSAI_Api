import json


class VirtualMachines(object):
    """Clase que utiliza xenapi para
        operar las maquinas virtuales"""

    def list(pool):

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
