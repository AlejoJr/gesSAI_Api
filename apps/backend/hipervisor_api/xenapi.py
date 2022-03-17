from XenAPI import XenAPI

from apps.backend.utils import get_env_setting


def conection(url, user, hipervisor_type):

    try:
        password = get_env_setting('XENAPI_PASS')
        #Conexion Xen
        if hipervisor_type == 'X':
            session = XenAPI.Session(url)
            session.login_with_password(user, password)
            print('Session Ref: ' + session._session)
            return session

        # Conexion Ovirt
        elif hipervisor_type == 'O':
            print('DESARROLLAR CONEXION OVIRT')

    except Exception as err:
        print(err)
        raise Exception(err)

