from os import environ
from django.core.exceptions import ImproperlyConfigured


def get_env_setting(setting):
    """Obtener la variable de entorno o retornar excepcion
    :param setting
    """
    try:
        return environ[setting]
    except KeyError:
        error_msg = "Set the %s env variable" % setting
        raise ImproperlyConfigured(error_msg)