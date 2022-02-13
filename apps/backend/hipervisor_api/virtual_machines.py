import json


class VirtualMachines(object):
    """Clase que utiliza xenapi para
        operar las maquinas virtuales"""

    def list(pool):

        virtual_machines = []

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

                data['name'] = vm['name_label']
                data['ref'] = vm['ref']
                data['uuid'] = vm['uuid']
                data['power_state'] = vm['power_state']

                # virtual_machine[data['name']] = data

                virtual_machines.append(data)

        return virtual_machines
