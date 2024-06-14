import sys, os
import logging
import argparse
import threading
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.examples.smbclient import MiniImpacketShell
from impacket import version
from impacket.smbconnection import SMBConnection
import ipaddress
from impacket.dcerpc.v5 import transport, scmr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from tabulate import tabulate
from winrm.protocol import Protocol
from tqdm import tqdm 

def print_banner():
    banner = """
 __   ___        __  ___  ___            
|__) |__   |\/| /  \  |  |__             
|  \ |___  |  | \__/  |  |___            
                                         
    __   ___  __   __     __             
   /__` |__  /__` /__` | /  \ |\ |       
   .__/ |___ .__/ .__/ | \__/ | \|       
                                         
       __        ___  __        ___  __  
      /  ` |__| |__  /  ` |__/ |__  |__) 
      \__, |  | |___ \__, |  \ |___ |  \ 
                                         by z3r082@redteam
"""
    print(banner)

def configure_logger(verbose):
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(message)s')
    return logging.getLogger(__name__)

def check_winrm(remote_host, username, password, domain, repite):
    try:
        status=0
        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remote_host
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_credentials(username, password, domain)
        dce = rpctransport.get_dce_rpc()
        # Conectar al servicio de administración de servicios
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)
        rpc = dce
        ans = scmr.hROpenSCManagerW(rpc)
        scManagerHandle = ans['lpScHandle']
        #resp = scmr.hREnumServicesStatusW(rpc, scManagerHandle)
        #sacar servicio solo winrm
        name = 'WinRM'
        ans = scmr.hROpenServiceW(rpc, scManagerHandle, name+'\x00')
        serviceHandle = ans['lpServiceHandle']
        logger.debug("Querying status for %s" % name)
        resp = scmr.hRQueryServiceStatus(rpc, serviceHandle)
        state = resp['lpServiceStatus']['dwCurrentState']
        if state == scmr.SERVICE_RUNNING:
            status = 1
        #fin
        """ for i in range(len(resp)):
            if(resp[i]['lpServiceName'][:-1]=='WinRM'):
                print("%30s - %70s - " % (resp[i]['lpServiceName'][:-1], resp[i]['lpDisplayName'][:-1]), end=' ')
                state = resp[i]['ServiceStatus']['dwCurrentState']
                if state == scmr.SERVICE_CONTINUE_PENDING:
                    print("CONTINUE PENDING")
                elif state == scmr.SERVICE_PAUSE_PENDING:
                    print("PAUSE PENDING")
                elif state == scmr.SERVICE_PAUSED:
                    print("PAUSED")
                elif state == scmr.SERVICE_RUNNING:
                    print("RUNNING")
                    status=1
                elif state == scmr.SERVICE_START_PENDING:
                    print("START PENDING")
                elif state == scmr.SERVICE_STOP_PENDING:
                    print("STOP PENDING")
                elif state == scmr.SERVICE_STOPPED:
                    print("STOPPED")
                else:
                    print("UNKNOWN")
        print("Total Services: %d" % len(resp)) """
        if(status!=1):
            if(repite==0):
                logger.debug("El servicio no esta corriendo. Tratamos de arrancarlo")
                scmr.hRStartServiceW(rpc, serviceHandle)
                scmr.hRCloseServiceHandle(rpc, serviceHandle)
                return check_winrm(remote_host, username, password, domain, 1)
            else:
                logger.debug("No es posible arrancar el servicio")
                dce.disconnect()
                return False
        else:
            logger.debug("El servicio ya esta arrancado")
            dce.disconnect()
            return True
        dce.disconnect()
    except Exception as e:
        logger.debug(f"Error obteniendo servicios en {remote_host}: {e}")
        return False

def check_admin(username, password, remote_host, domain='',lmhash='',nthash='', port=445):
    try:
        smbClient = SMBConnection(remote_host, remote_host, sess_port=int(port))
    except Exception as e:
        logger.debug(f"Excepción al intentar conectar a {remote_host}: {e}")
        return False
    try:
        smbClient.login(username, password, domain, lmhash, nthash)
    except Exception as e:
        logger.debug(f"Error en {remote_host}: {e}")
        logger.debug("Posibles malas credenciales")
        return False
    try:
        shared_device = 'C$'  # Recurso compartido C$
        remote_file_path = r'\Windows\System32\drivers\etc\hosts'  # Ruta al archivo hosts en el host remoto
        tree_id = smbClient.connectTree(shared_device)
        #print(f"treeId para el recurso compartido '{shared_device}': {tree_id}")
        hosts=smbClient.openFile(treeId=tree_id,pathName=remote_file_path)
        #print(hosts)
        content_bytes = smbClient.readFile(treeId=tree_id,fileId=hosts)
        #content_str = content_bytes.decode('utf-8')
        #print(f"Contenido del archivo hosts en {remote_host}:\n{content_str}")
        if(len(content_bytes)>0):
            logger.debug("Es administrador")
            smbClient.close()
            return True
        else:
            logger.debug("No es administrador")
            smbClient.close()
            return False
    except Exception as e:
        logger.debug(f"Error en {remote_host}: {e}")
        logger.debug("Usuario no es administrador")
        smbClient.close()
        return False

def is_ip_or_hostname_or_cidr(input_string):
    try:
        network = ipaddress.ip_network(input_string, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        if os.path.isfile(input_string):
            with open(input_string, 'r') as file:
                return [line.strip() for line in file]
        else:
            return [input_string]
        
def extract_usernames(output):
    lines = output.replace('\r', '').split('\n')
    usernames = []
    for line in lines[1:]:  # Saltamos la primera línea de cabecera
        if line.strip():  # Asegurarse de que no está vacío
            # Extraer el nombre de usuario (asumimos que está en la primera columna)
            username = line.split()[0]
            usernames.append(username)
    return usernames

def run_quser(remote_host, username, password):
    p = Protocol(
        endpoint=f'http://{remote_host}:5985/wsman',
        transport='ntlm',
        username=username,
        password=password,
        server_cert_validation='ignore')
    shell_id = p.open_shell()
    command_id = p.run_command(shell_id, 'quser')
    std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
    p.cleanup_command(shell_id, command_id)
    p.close_shell(shell_id)
    if(status_code==0):
        salida=std_out.decode('utf-8')
        return extract_usernames(salida)
    else:
        error=std_err.decode('utf-8')
        logger.debug(f'Se ha producido un error {error}')
        if("No existe un usuario" in error):
            return "Sin sesion activa"
        else:
            return error

def process_host(host, username, password, domain, data, lock, pbar):
    sessiones=''
    is_admin='False'
    winrm='False'
    logger.debug(host)
    nueva_data = []
    is_admin=check_admin(username, password, host, domain)
    if(is_admin):
        winrm=check_winrm(host, username, password, domain, 0)
        if(winrm):
            sessiones=run_quser(host, username, password)
    nueva_data = [host, username, password, is_admin, winrm, sessiones]
    with lock:
        data.append(nueva_data)
    pbar.update(1)

if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description="Script para obtener las sesiones remotas")
    parser.add_argument('-u', '--username', required=True, help='Username')
    parser.add_argument('-p', '--password', required=True, help='Password')
    parser.add_argument('-i', '--host_or_file_or_cidr', required=True, help='Host, file, or CIDR')
    parser.add_argument('-d', '--domain', default='', help='Domain')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()
    logger = configure_logger(args.verbose)
    hosts = is_ip_or_hostname_or_cidr(args.host_or_file_or_cidr)
    data = [["Host", "User", "Pass", "Is_Admin", "WinRM_Running", "Sessions"]]
    lock = threading.Lock()
    threads = []
    with tqdm(total=len(hosts), desc="Procesando hosts") as pbar:
        for host in hosts:
            thread = threading.Thread(target=process_host, args=(host, args.username, args.password, args.domain, data, lock, pbar))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
    print(tabulate(data, headers="firstrow", tablefmt="grid"))
