#! /usr/bin/python3

import logging
import threading
import queue
import os
from typing import Any, Dict
import json
import argparse
import subprocess
import sys
import getpass
import venv
import socket
import time
import copy

os.environ['PYTHONUNBUFFERED'] = '1'

logging.basicConfig(filename='nebdeploy.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(lineno)d - %(message)s')
logging.info("======================================= Startup =======================================")
required_modules = ['requests', 'paramiko', 'scp', 'yaml']

def set_mode(args):
    global mode
    if args.preinstall:
        mode = "preinstall"
    elif args.uninstall:
        mode = "uninstall"
    elif args.running:
        mode = "running"
    elif args.install:
        mode = "install"
    else:
        mode = "usage"
    

class NebulaDeployUtil:

    class UnsupportedDistro(Exception):
        pass

    class UnsupportedOS(Exception):
        pass
    
    class UnsupportedArch(Exception):
        pass
    
    class UnreachableHost(Exception):
        pass

    class FailedToRunAsRoot(Exception):
        pass

    class ErrorGeneratingHostCertificate(Exception):
        pass

    def __init__(self, config_file: str):
        self.check_and_create_venv()
        self.check_and_install_modules()
        self.config = self.read_json_file(config_file)
        for host in self.get_hosts():
            self.config['hosts'][host]['store_password'] = True
            if 'password'  not in self.config['hosts'][host]:
                self.config['hosts'][host]['store_password'] = False
            
            self.config['hosts'][host]['store_username'] = True
            if 'username'  not in self.config['hosts'][host]:
                self.config['hosts'][host]['store_username'] = False

        if self.config.get('debug', False):
            logging.getLogger().setLevel(logging.DEBUG)
            logging.debug("Debug logging enabled.")

        self.configyml = self.download_config()
        logging.info("Default configuration downloaded successfully.")

        self.active_host = {}
        self.ssh_client = None 
        logging.info(f"LogLevel set to: {logging.getLogger().level}")

    def check_reachability(self):
        address = self.active_host['address']
        response = os.system(f"ping -c 1 {address} > /dev/null")
        if response != 0:
            logging.warning(f"Host {address} is not reachable.")
            raise self.UnreachableHost(f"{self.active_host['name']}:{address} is unreachable.")
        logging.info(f"Host {address} is reachable.")

    def get_hosts(self):
        enabled_hosts = [
            host for host, config in self.config['hosts'].items()
            if not config.get('disabled', False)
        ]

        enabled_hosts.sort(key=lambda host: self.config['hosts'][host].get('lighthouse', False), reverse=True)
        return enabled_hosts

    def download_config(self):
        url = "https://raw.githubusercontent.com/slackhq/nebula/master/examples/config.yml"
        logging.info("Downloading default configuration from: {}".format(url))
        try:
            response = requests.get(url)
            response.raise_for_status()
            return(yaml.safe_load(response.text))
        except Exception as e:
            logging.error(f"Failed to download default configuration: {e}")
            raise

    def write_config_to_file(self):
        logging.info("Writing config to config.json")
        for host in self.get_hosts():                
            if not self.config['hosts'][host]['store_password']:
                del self.config['hosts'][host]['password']
            del self.config['hosts'][host]['store_password']
            
            if not self.config['hosts'][host]['store_username']:
                del self.config['hosts'][host]['username']
            del self.config['hosts'][host]['store_username']

        try:
            with open('config.json', 'w') as json_file:
                json.dump(self.config, json_file, indent=4)
                logging.info("Configuration written to config.json successfully.")
        except Exception as e:
            logging.error(f"Failed to write configuration to file: {e}")

    def read_json_file(self, filepath: str) -> Dict[str, Any]:
        with open(filepath, 'r') as json_file:
            return json.load(json_file)

    def check_and_create_venv(self):
        if hasattr(sys, 'ps1'):  # interactive shell
            logging.info("Running in interactive mode — skipping venv enforcement.")
        return
        logging.debug("Checking and creating virtual environment...")
        venv_dir = os.path.join(os.getcwd(), "venv")
        venv_python = os.path.join(venv_dir, "bin", "python")

        if not os.path.exists(venv_python):
            subprocess.check_call([sys.executable, "-m", "venv", venv_dir])
            logging.info("Virtual environment created.")

        if os.environ.get("IN_VENV") != "1":
            os.environ["IN_VENV"] = "1"
            os.execv(venv_python, [venv_python] + sys.argv)

    def check_and_install_modules(self):
        if os.system("pip3 --version > /dev/null 2>&1"):
            logging.error("pip3 not installed")
            print("pip3 not installed")
            sys.exit(1)
        logging.debug("Checking and installing required modules...")
        max_retries = 3
        for module in required_modules:
            for attempt in range(max_retries):
                try:
                    globals()[module] = __import__(module)
                    logging.info(f"{module} is already installed.")
                    break
                except ImportError:
                    logging.warning(f"{module} not found. Installing...")
                    subprocess.check_call([sys.executable, '-m', 'pip', 'install', module])
                    logging.info(f"{module} installed successfully.")
                    continue
            else:
                logging.error(f"Failed to import {module} after {max_retries} attempts")
                print(f"Failed to import {module} after {max_retries} attempts")
                sys.exit(1)

    def ensure_credentials(self):
        for host in self.get_hosts():
            if 'username' not in self.config['hosts'][host]:
                logging.warning(f"Username not defined for host {host}. Prompting user.")
                print(f"Username not defined for host {host}.", flush=True)
                username = input("Please enter the username: ")
                self.config['hosts'][host]['username'] = username  # Store the entered username

            if 'password' not in self.config['hosts'][host]:
                logging.warning(f"Password not defined for user {username} on host {host}. Prompting user.")
                print(f"Password not defined for user {username} on host {host}.", flush=True)
                password = getpass.getpass(f"Please enter the password for {username}: ")
                self.config['hosts'][host]['password'] = password
    
    def set_active_host(self, host):
        self.ssh_client = self.create_ssh_client(self.config['hosts'][host]['address'], 22, self.config['hosts'][host]['username'], self.config['hosts'][host]['password'])
        self.active_host = {**{"name": host}, **self.config['hosts'][host] }
        print(f"Host: {self.active_host['name']}:\t", end='', flush=True)
        logging.info(f"Host: {self.active_host['name']}")    

    def removebindir(self):
        logging.info(f"Removing bindir {self.config['bindir']} on {self.active_host['name']}...")
        command = f"rm -rf {self.config['bindir']}"
        self.execute_command(command)
        logging.info(f"Removed bindir {self.config['bindir']} on {self.active_host['name']}.")

    def removeetcdir(self):
        logging.info(f"Removing etcdir {self.config['etcdir']} on {self.active_host['name']}...")
        command = f"rm -rf {self.config['etcdir']}"
        self.execute_command(command)
        logging.info(f"Removed etcdir {self.config['etcdir']} on {self.active_host['name']}.")

    def identify_host(self):
        self.active_host['os_name'] = self.execute_command(f"uname")
        self.active_host['arch'] = self.execute_command(f"uname -i")
        self.active_host['proc'] = self.execute_command(f"uname -p")
 
    def transfer_tarball(self):
        logging.info(f"Active Host: {self.active_host}")
        if self.active_host['os_name'] == "Linux":
            if self.active_host['arch'] == "x86_64": 
                self.active_host['arch'] = "amd64"
                self.active_host['os_name']=self.active_host['os_name'].lower()
            else:
                raise self.UnsupportedArch(f"Unsupported Architecture: {arch}")
        elif self.active_host['os_name'] == "Isilon OneFS":
            self.active_host['os_name'] = "freebsd"
            self.active_host['arch'] = self.active_host['proc']
        else:
            raise self.UnsupportedOS(f"Unsupported OS: {self.active_host['os_name']}")
        tarball_name = f"nebula-{self.active_host['os_name']}-{self.active_host['arch']}.tar.gz"
        self.scp_to_directory(os.path.join(os.getcwd(), tarball_name), self.config['tmpdir'])
        return tarball_name

    def check_run_as_root(self):
        command = "whoami"
        logging.info("Checking if the script is running as root...")
        user = self.execute_command(command)
        logging.debug(f"user: {user}")
        if user != "root":
            logging.error(f"Script is not running as root, current user: {user}")
            raise self.FailedToRunAsRoot("The script must be run as root.")
        logging.info("Script is running as root.")
        
    def set_host_status(self, state, error=""):
        self.config['hosts'][self.active_host['name']]["state"] = state
        self.config['hosts'][self.active_host['name']]["statetimestamp"] = time.time()
        self.config['hosts'][self.active_host['name']]['error'] = error
        if error:
            logging.info(f"Install error on {self.active_host['name']} - {error}")
            print(f"Install error on {self.active_host['name']} - {error}")
            print("\033[91m✘ Failed\033[0m")

    def execute_command(self, command, timeout=30):
        try:
            use_sudo = self.active_host.get('sudo', False)
            full_command = command
            if use_sudo:
                # Prepend sudo with -S and empty prompt to suppress prompt text
                full_command = f"sudo -S -p '' {command}"

            logging.info(f"Executing command: {full_command}")
            transport = self.ssh_client.get_transport()
            channel = transport.open_session()
            channel.exec_command(full_command)

            out_data = ''
            err_data = ''
            start_time = time.time()
            password_sent = False
            while True:
                if channel.recv_ready():
                    out_chunk = channel.recv(1024).decode()
                    out_data += out_chunk
                if channel.recv_stderr_ready():
                    err_chunk = channel.recv_stderr(1024).decode()
                    err_data += err_chunk

                # If sudo is used and password not sent yet, check if sudo is waiting for password
                if use_sudo and not password_sent:
                    # Check if channel is still open and waiting for input
                    if not channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                        # Send password + newline
                        channel.send(self.active_host['password'] + '\n')
                        password_sent = True

                if channel.exit_status_ready():
                    break

                if time.time() - start_time > timeout:
                    channel.close()
                    raise TimeoutError(f"Command timeout: {full_command}")

                time.sleep(0.1)

            # Read any remaining output after exit
            while channel.recv_ready():
                out_data += channel.recv(1024).decode()
            while channel.recv_stderr_ready():
                err_data += channel.recv_stderr(1024).decode()

            exit_status = channel.recv_exit_status()

            if out_data:
                logging.info(f"Command output: {out_data.strip()}")
            if err_data:
                logging.error(f"Command error: {err_data.strip()}")
            if exit_status != 0:
                raise Exception(f"Command failed: {full_command}, Exit status: {exit_status}, Error: {err_data.strip()}")

            return out_data.strip()

        except Exception:
            logging.exception(f"Failed to execute command: {command}")
            raise

    def scp_to_directory(self, filename, targetdir):
        with scp.SCPClient(self.ssh_client.get_transport()) as scp_client:
            scp_client.put(filename, f"{targetdir}/{os.path.basename(filename)}")
            logging.info(f"Transferred {filename} to {targetdir}/")

    def check_distribution(self):
        try:
            logging.info(f"Checking OS")

            logging.info(f"os_name: {self.active_host['os_name']}")
            os_name = self.active_host['os_name']
            if not any(os_name in list(os_dict.keys())[0] for os_dict in self.config["supported_os"]):
                raise self.UnsupportedOS(f"Unsupported OS: {self.active_host['os_name']}")
        except Exception as e:
            logging.error(f"Error checking os: {e}")
            raise
        try:
            if os_name == "linux":
                logging.info(f"Checking Distro")
                stdout = self.execute_command("grep '^ID=' /etc/os-release | awk -F= '{print $2}'")
                distro = stdout.strip().lower()
                if not any(distro in os_dict[list(os_dict.keys())[0]]["distro"] for os_dict in self.config["supported_os"] if list(os_dict.keys())[0] == "Linux"):
                    raise self.UnsupportedDistro(f"Unsupported Distro: {distro}")
        except Exception as e:
            logging.error(f"Error checking distribution: {e}")
            raise

    def download_file(self, url, dest):
        if os.path.exists(dest):
            logging.info(f"File already exists: {dest}. Skipping download.")
            return 
        logging.debug(f"Starting download from {url} to {dest}...")
        try:
            import requests
            response = requests.get(url, stream=True)
            response.raise_for_status()
            
            with open(dest, 'wb') as file:
                for chunk in response.iter_content(chunk_size=8192):
                    file.write(chunk)
            logging.info(f"Download completed: {dest}")
        except Exception as e:
            logging.error(f"Error downloading file: {e}")
            raise Exception(f"Download failed for {url}: {e}")

    def create_ssh_client(self, server, port, user, password):
        import paramiko
        logging.debug(f"Creating SSH client for {server}...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(server, port=port, username=user, password=password)
            logging.info(f"Connected to {server} as {user}.")
        except Exception as e:
            logging.error(f"Failed to connect to {server} as {user}: {e}")
            raise
        return client

    def check_path_exists(self, path):
        if not self.execute_command(f'sudo -S -p '' test -e "/tmp/nebdeploy" || true && echo exists') == "exists":
            return False
        return True

    def generate_configs(self):
        
        self.configlh = copy.deepcopy(self.configyml)
        self.confignonlh = copy.deepcopy(self.configyml)
        lhhosts = []

        for host in self.get_hosts():
            if self.config['hosts'][host]['lighthouse']:
                lhhosts.append(host)

        self.configlh['lighthouse']['am_lighthouse'] = True
        self.confignonlh['lighthouse']['am_lighthouse'] = False
        self.configlh['lighthouse']['hosts'] = []
        self.confignonlh['lighthouse']['hosts'] = []

        for host in lhhosts:
            #self.configlh['lighthouse']['hosts'].append(self.config['hosts'][host]['nebulaaddress'])
            self.confignonlh['lighthouse']['hosts'].append(self.config['hosts'][host]['nebulaaddress'])
            
        static_host_map = {}
        for host in self.get_hosts():
            static_host_map[self.config['hosts'][host]['nebulaaddress']] = [ f"{self.config['hosts'][host]['address']}:4242"]
            
        self.configlh['static_host_map'] = static_host_map
        self.confignonlh['static_host_map'] = static_host_map
        self.configlh['firewall']['inbound'] = [
            {
                    'port': 22,
                    'proto': 'tcp',
                    'host': 'any'
                },
                {
                    'proto': 'icmp',
                    'host': 'any'
                }
            ]
        self.confignonlh['firewall']['inbound'] = [
            {
                'port': 8080,
                'proto': 'tcp',
                'host': 'any'        # changed from 'isilon' to 'any'
            },
            {
                'port': 2049,
                'proto': 'tcp',
                'host': 'any'        # changed from 'isilon' to 'any'
            },
            {
                'port': 2049,
                'proto': 'udp',
                'host': 'any'        # changed from 'isilon' to 'any'
            },
            {
                'port': 22,
                'proto': 'tcp',
                'host': 'any'
            },
            {
                    'proto': 'icmp',
                    'host': 'any'
            }
        ]
        
        self.configlh['pki']['ca'] = '/opt/nebula/etc/ca.crt'
        self.configlh['pki']['cert'] = '/opt/nebula/etc/host.crt'
        self.configlh['pki']['key'] = '/opt/nebula/etc/host.key'
        self.confignonlh['pki']['ca'] = '/opt/nebula/etc/ca.crt'
        self.confignonlh['pki']['cert'] = '/opt/nebula/etc/host.crt'
        self.confignonlh['pki']['key'] = '/opt/nebula/etc/host.key'

        with open('config/config-lighthouse.yml', 'w') as f:
            yaml.dump(self.configlh, f, default_flow_style=False)

        with open('config/config-nonlighthouse.yml', 'w') as f:
            yaml.dump(self.confignonlh, f, default_flow_style=False)

    def preinstall(self):
        logging.info("Starting Preinstall Verification")
        print("Starting Preinstall Verification", flush=True)
        for host in self.get_hosts():
            try:
                self.set_active_host(host)
                self.identify_host()
                self.check_reachability()
                self.ssh_client = self.create_ssh_client(self.active_host['address'], 22, self.active_host['username'], self.active_host['password'])
                self.check_distribution()
                self.check_run_as_root()
                print("  \033[92m✔ Passed\033[0m")
            except Exception as err:
                logging.error(err)
                print(err)

    def install(self):
        logging.info("Starting Host Install")
        self.generate_configs()

        for host in self.get_hosts():
            try:
                if 'state' not in self.config['hosts'][host] or not self.config['hosts'][host]['state'] or self.config['hosts'][host]['state'] != "installed": 
                    self.set_active_host(host)
                    self.identify_host()
                    self.check_reachability()
                    self.check_distribution()
                    self.check_run_as_root()
                    self.execute_command(f"whoami")
                    self.execute_command(f"mkdir -p {self.config['bindir']}")
                    self.execute_command(f"chown root {self.config['bindir']}")
                    self.execute_command(f"chmod 755 {self.config['bindir']}")

                    self.execute_command(f"mkdir -p {self.config['etcdir']}")
                    self.execute_command(f"chown root {self.config['etcdir']}")
                    self.execute_command(f"chmod 700 {self.config['etcdir']}")

                    self.execute_command(f"mkdir -p {self.config['tmpdir']}")
                    self.execute_command(f"chmod 777 {self.config['tmpdir']}")

                    tarballname = self.transfer_tarball()
                    
                    self.execute_command(f"tar -xzf {self.config['tmpdir']}/{tarballname} -C {self.config['bindir']}")

                    # Generate Certificates
                    
                    
                    
                    cmd = [
                        'bin/nebula-cert', 'sign',
                        '-name', host,
                        '-ip', f"{self.active_host['nebulaaddress']}/24",
                        '-out-crt', f"certificates/{host}.crt",
                        '-out-key', f"certificates/{host}.key",
                        '-ca-crt', "certificates/ca.crt",
                        '-ca-key', "certificates/ca.key"
                    ]

                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode != 0:
                        raise ErrorGeneratingHostCertificate(f"Error Generating Host Cert: {result.stdout} {result.stderr}")
                    
                    logging.info("Deploying Configfile")
                    if self.active_host['lighthouse']:
                        self.scp_to_directory(os.path.join(os.getcwd(), 'config',  'config-lighthouse.yml'), self.config['tmpdir'])
                        self.execute_command(f"mv {self.config['tmpdir']}/config-lighthouse.yml {self.config['etcdir']}/config.yml")
                    else:
                        self.scp_to_directory(os.path.join(os.getcwd(), 'config',  'config-nonlighthouse.yml'), self.config['tmpdir'])
                        self.execute_command(f"mv {self.config['tmpdir']}/config-nonlighthouse.yml {self.config['etcdir']}/config.yml")
                    
                    logging.info("Deploying CA Certificate")
                    self.scp_to_directory(os.path.join(os.getcwd(), 'certificates',  'ca.crt'), self.config['tmpdir'])
                    self.execute_command(f"mv {self.config['tmpdir']}/ca.crt {self.config['etcdir']}/ca.crt")

                    logging.info("Deploying Host Certificate")
                    self.scp_to_directory(os.path.join(os.getcwd(), 'certificates',  f'{host}.crt'), self.config['tmpdir'])
                    self.execute_command(f"mv {self.config['tmpdir']}/{host}.crt {self.config['etcdir']}/host.crt")

                    logging.info("Deploying Host Key")
                    self.scp_to_directory(os.path.join(os.getcwd(), 'certificates',  f'{host}.key'), self.config['tmpdir'])
                    self.execute_command(f"mv {self.config['tmpdir']}/{host}.key {self.config['etcdir']}/host.key")
                    
                    self.scp_to_directory(os.path.join(os.getcwd(), 'scripts',  'startnebula.sh'), self.config['tmpdir'])
                    self.execute_command(f"mv {self.config['tmpdir']}/startnebula.sh {self.config['bindir']}")

                    self.scp_to_directory(os.path.join(os.getcwd(), 'scripts',  'stopnebula.sh'), self.config['tmpdir'])
                    self.execute_command(f"mv {self.config['tmpdir']}/stopnebula.sh {self.config['bindir']}")

                    self.execute_command(f"chown -R root:daemon {self.config['bindir']}")
                    self.execute_command(f"chmod -R 750 {self.config['bindir']}")
                    self.execute_command(f"chown -R root:daemon {self.config['etcdir']}")
                    self.execute_command(f"chmod 600 {self.config['etcdir']}/ca.crt")
                    self.execute_command(f"chmod 600 {self.config['etcdir']}/host.crt")
                    self.execute_command(f"chmod 600 {self.config['etcdir']}/host.key")
                    self.execute_command(f"chmod 600 {self.config['etcdir']}/config.yml")

                    logging.info("Starting Nebula, logging to /tmp/nebula.log")
                    self.execute_command(f"bash /opt/nebula/bin/startnebula.sh")
                    
                    #command = "/opt/nebula/bin/startnebula.sh"
                    #print(self.execute_command(command))
                    
                    
                    # if self.active_host['os_name'] == "linux" and self.check_path_exists(f"/etc/systemd"):
                    #     logging.info("Configuring systemd")
                    #     self.scp_to_directory(os.path.join(os.getcwd(), 'payload', 'nebula.service'), self.config['tmpdir'])
                    #     self.execute_command(f"cp {self.config['tmpdir']}/nebula.service /etc/systemd/system")
                    #     self.execute_command("echo systemctl daemon-reexec")
                    #     self.execute_command("echo systemctl daemon-reload")
                    #     self.execute_command("echo systemctl enable nebula")
                    #     self.execute_command("echo systemctl start nebula")
                    # else:
                    #     logging.info("Configuring rc.local")
                        # run rclocal setup
                    # self.copy_to_target_location(temp_dir, self.config['etcdir'])
                    #if temp_dir != "": self.execute_command(f"rm -rf {temp_dir}")
                    self.set_host_status("installed")
                    # if self.check_path_exists(self.config['tmpdir']):
                    #     self.execute_command(f"rm -rf {self.config['tmpdir']}")
                else:
                    logging.info(f"Already installed {host}, skipping")
                    print(f"Already installed {host}, skipping", flush=True)
            except Exception as err:
                self.set_host_status("error", str(err))

            logging.info(f"Finished install of host: {host}")

            print("Installed", flush=True)
        logging.info(f"Finished install of all hosts")
        self.write_config_to_file()

    def uninstall(self):
        for host in self.get_hosts():
            try:
                self.set_active_host(host)
                self.ssh_client = self.create_ssh_client(self.active_host['address'], 22, self.active_host['username'], self.active_host['password'])
                self.execute_command(f"bash /opt/nebula/bin/stopnebula.sh")
                if self.check_path_exists(self.config['bindir']):
                    self.execute_command(f"rm -rf {self.config['bindir']}")
                if self.check_path_exists(self.config['etcdir']):
                    self.execute_command(f"rm -rf {self.config['etcdir']}")
                if self.check_path_exists(self.config['tmpdir']):
                    self.execute_command(f"rm -rf {self.config['tmpdir']}")
                if self.check_path_exists('/tmp/nebula.log'):
                    self.execute_command(f"rm -f /tmp/nebula.log")
                self.set_host_status("uninstalled")
                print("Removed", flush=True)
            except Exception as err:
                self.set_host_status("error", str(err))

        self.write_config_to_file()

        # local cleanup
        for dir in [ 'bin', 'certificates', 'config' ]:
            dir = os.path.join(os.getcwd(), dir)
            if os.path.exists(dir):
                os.system(f'rm -rf {dir}')
        os.system('rm -f nebula-*.tar.gz')
    def running(self):
        for host in self.get_hosts():
            try:
                
                self.set_active_host(host)
                self.identify_host()
                self.ssh_client = self.create_ssh_client(self.active_host['address'], 22, self.active_host['username'], self.active_host['password'])
                if self.active_host['os_name'] == "Linux":
                    output = self.execute_command(f"ps -ef | grep /opt/nebula/bin/nebula | grep -v grep || echo ")
                elif self.active_host['os_name'] == "Isilon OneFS":
                    output = self.execute_command(f"ps aux| grep /opt/nebula/bin/nebula | grep -v grep || echo ")
                if output:
                    print(f"Running")
                else:
                    print("Not Running")
            except Exception as err:
                print(err)

if __name__ == "__main__":
    deploy_util = NebulaDeployUtil('config.json')

    # Get arguments
    parser = argparse.ArgumentParser(description='Nebula Deployment Script')
    parser.add_argument('-u', '--uninstall', action='store_true', help='Remove Nebula from all hosts')
    parser.add_argument('-p', '--preinstall', action='store_true', help='Preinstall verification')
    parser.add_argument('-r', '--running', action='store_true', help='Check to see if running')
    parser.add_argument('-i', '--install', action='store_true', help='Check to see if running')
    args = parser.parse_args()

    set_mode(args)

    # Check to make sure we have the credentials to act before starting to loop on the hosts
    deploy_util.ensure_credentials()

    # Determine which mode to operate in
    if mode == "uninstall":
        deploy_util.uninstall()
    elif mode == "install":
        logging.info("Downloading binary tarballs from github")
        urls = [
            "https://github.com/slackhq/nebula/releases/download/v1.9.5/nebula-freebsd-amd64.tar.gz",
            "https://github.com/slackhq/nebula/releases/download/v1.9.5/nebula-linux-amd64.tar.gz"
        ]
        
        threads = []
        for url in urls:
            dest_path = os.path.join(os.getcwd(), os.path.basename(url))
            download_thread = threading.Thread(target=deploy_util.download_file, args=(url, dest_path))
            threads.append(download_thread)
            download_thread.start()

        for thread in threads:
            thread.join()
        logging.info("All downloads completed.")

        if not os.path.exists('certificates'):
            os.mkdir('certificates')
        
        host_os = subprocess.check_output(['uname']).decode().strip().lower()
        if subprocess.check_output(['uname', '-p']).decode().strip() == "x86_64":
            host_arch = "amd64"
        else:
            host_arch = subprocess.check_output(['uname', '-p']).decode().strip()

        if not os.path.exists('bin'):
            os.mkdir('bin')
        if not os.path.exists('bin/nebula') or not os.path.exists('bin/nebula-cert'):
            os.system(f"tar zxf nebula-{host_os}-{host_arch}.tar.gz -C bin/")
        
        if not os.path.exists('config'):
            os.mkdir('config')

        if not os.path.exists('certificates/ca.crt'):
            org = deploy_util.config.get('organization', "demo")
            os.system(f"bin/nebula-cert ca -name {org} -out-crt certificates/ca.crt -out-key certificates/ca.key")

        deploy_util.install()
    elif mode == "running":
        deploy_util.running()
    elif mode == "usage":
        parser.print_usage()
    else:
        parser.print_usage()
        
