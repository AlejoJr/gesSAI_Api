from django.db import connections

#Consultar en la BD Oracle, La conexion ya se hizo al iniciar el sistema en el archivo (gesSAI/__init__.py)
def selectSQL(sql, var=None, alias='default'):

    try:
        cursor = connections[alias].cursor()

        if var is not None:
            cursor.execute(sql, var)
        else:
            cursor.execute(sql)

        return cursor.fetchall()

    except Exception:
        raise Exception(sql, 'ERROR DE SQL', Exception)