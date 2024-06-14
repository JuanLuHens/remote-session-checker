# Remote Session Checker

## Descripción

`Remote Session Checker` es un script en Python que permite verificar las sesiones activas en un sistema windows. Para ello, comprueba si el usuario tiene privilegios de administrador en la/s máquina remota, comprobar si el servicio WinRM está en funcionamiento, sino lo está levanta el servicio WinRM y lista las sesiones activas de los usuarios en dicha máquina.

## Requisitos

- Python 3.x
- `pip` para gestionar paquetes de Python

## Instalación

1. Clona el repositorio:
    ```sh
    git clone https://github.com/juanlhens/remote-session-checker.git
    cd remote-session-checker
    ```

2. Instala las dependencias:
    ```sh
    pip install -r requirements.txt
    ```

## Uso

Ejecuta el script con los siguientes parámetros:

```sh
python3 get-sesiones.py -u USERNAME -p PASSWORD -i HOST_OR_FILE_OR_CIDR [-d DOMAIN] [-v]
```
### Parámetros
```sh
-u, --username: Nombre de usuario.
-p, --password: Contraseña.
-i, --host_or_file_or_cidr: Host, archivo con una lista de hosts, o rango CIDR.
-d, --domain: (Opcional) Dominio.
-v, --verbose: (Opcional) Habilita la salida detallada.
```

## Ejemplo
```sh
python3 get-sesiones.py -u superad -p 12345Abc@# -i 172.24.76.0/29 -v
```
Este comando verificará los privilegios de administrador, el estado de WinRM y las sesiones activas para cada host en el rango 172.24.76.0/29, usando las credenciales proporcionadas.

### Resultado
```sh
+-------------+---------+------------+------------+-----------------+------------------+
| Host        | User    | Pass       | Is_Admin   | WinRM_Running   | Sessions         |
+=============+=========+============+============+=================+==================+
| 172.24.76.6 | superad | 12345Abc@# | True       | True            | ['user1']        |
+-------------+---------+------------+------------+-----------------+------------------+
| 172.24.76.3 | superad | 12345Abc@# | True       | True            | ['user1', 'jkl'] |
+-------------+---------+------------+------------+-----------------+------------------+
| 172.24.76.1 | superad | 12345Abc@# | False      | False           |                  |
+-------------+---------+------------+------------+-----------------+------------------+
| 172.24.76.4 | superad | 12345Abc@# | False      | False           |                  |
+-------------+---------+------------+------------+-----------------+------------------+
| 172.24.76.2 | superad | 12345Abc@# | True       | True            | ['user157643']   |
+-------------+---------+------------+------------+-----------------+------------------+
| 172.24.76.5 | superad | 12345Abc@# | True       | True            | ['user157508']   |
+-------------+---------+------------+------------+-----------------+------------------+


```


## Contribuciones
¡Las contribuciones son bienvenidas! Por favor, abre un issue o envía un pull request.

## Licencia
Este proyecto está bajo la licencia MIT. Para más detalles, consulta el archivo LICENSE.