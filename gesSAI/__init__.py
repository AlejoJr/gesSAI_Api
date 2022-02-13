import cx_Oracle
import pymysql

from apps.backend.utils import get_env_setting

#Inicializar bd Mysql
pymysql.install_as_MySQLdb()

#Inicializar BD Oracle
cx_Oracle.init_oracle_client(lib_dir= get_env_setting('ORACLE_HOME'),config_dir= get_env_setting('TNS_ADMIN'))
