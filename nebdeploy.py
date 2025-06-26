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

# Configure logging
logging.basicConfig(filename='nebdeploy.log', level=logging.DEBUG,
                    format='%(asctime)s - %(message)s - %(levelname)s')  # Adjusted format
logging.Formatter.converter = time.gmtime  # Log in UTC


# Get hostname
hostname = socket.gethostname()
logging.info(f"Script started on host: {hostname}")

nebplatforms = [ ]
freebsd = "https://github.com/slackhq/nebula/releases/download/v1.9.5/nebula-freebsd-amd64.tar.gz"
linux = "https://github.com/slackhq/nebula/releases/download/v1.9.5/nebula-linux-amd64.tar.gz"
nebplatforms = [ freebsd, linux ]

required_modules = ['requests', 'paramiko', 'scp', 'yaml']
supported_os = [ "linux", "freebsd", "isilon onefs"]

class NebulaDeployUtil:
    def __init__(self, config_file: str):
        self.check_and_create_venv()
        self.check_and_install_modules()
        self.config = self.read_json_file(config_file)
        self.configyml = self.download_config()
        logging.info("Default configuration downloaded successfully.")
        self.active_host = {}
        self.ssh_client = None
        self.use_sudo = False  

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
        logging.debug("Checking and installing required modules...")
        for module in required_modules:
            try:
                globals()[module] = __import__(module)
                logging.info(f"{module} is already installed.")
            except ImportError:
                logging.warning(f"{module} not found. Installing...")
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', module])
                logging.info(f"{module} installed successfully.")
                try:
                    globals()[module] = __import__(module)
                except ImportError:
                    logging.error(f"Failed to import {module} after install")
                    print(f"Failed to import {module} after install")
                    sys.exit(1)

    def ensure_credentials(self):
        for host in self.config['hosts'].values():
            self.prompt_for_credentials(host)

    def prompt_for_credentials(self, host):
        username = host.get('username')
        password = host.get('password')

        if not username:
            logging.warning(f"Username not defined for host {host['address']}. Prompting user.")
            print(f"Username not defined for host {host['address']}.")
            username = input("Please enter the username: ")
            host['username'] = username  # Store the entered username

        if not password:
            logging.warning(f"Password not defined for user {username} on host {host['address']}. Prompting user.")
            print(f"Password not defined for user {username} on host {host['address']}.")
            password = getpass.getpass(f"Please enter the password for {username}: ")
            host['password'] = password
    
    def uninstall(self):
        for host in self.config['hosts']:
            self.active_host = {**{"name": host}, **self.config['hosts'][host] }
            print(f"Host: {self.active_host['name']}")
            if not self.ssh_client:
                self.ssh_client = self.create_ssh_client(self.config['hosts'][host]['address'], 22, self.config['hosts'][host]['username'], self.config['hosts'][host]['password'])
            self.removetmpdirs()

    def install(self):
        task_queue = queue.Queue()
        logging.info("Starting download...")
        threads = []
        
        for url in nebplatforms:
            dest_path = os.path.join(os.getcwd(), os.path.basename(url))
            download_thread = threading.Thread(target=self.download_file, args=(url, dest_path))
            threads.append(download_thread)
            download_thread.start()

        for thread in threads:
            thread.join()

        logging.info("All downloads completed.")

        logging.info("Reading Config...")
        
        logging.info("Starting host setup")
        for host in self.config['hosts']:
            self.active_host = {**{"name": host}, **self.config['hosts'][host] }
            print(f"Host: {self.active_host['name']}")
            if self.ssh_client is None or self.ssh_client.get_transport() is None or not self.ssh_client.get_transport().is_active():
                self.ssh_client = self.create_ssh_client(self.config['hosts'][host]['address'], 22, self.config['hosts'][host]['username'], self.config['hosts'][host]['password'])
            self.check_distribution()

            if self.config['hosts'][host]['sudo']:
                self.use_sudo = True
            else:
                self.use_sudo = False
            logging.info(f"Selecting Host: {host}:{self.config['hosts'][host]}")
            if not self.ssh_client:
                self.ssh_client = self.create_ssh_client(self.config['hosts'][host]['address'], 22, self.config['hosts'][host]['username'], self.config['hosts'][host]['password'])
            self.create_directories()
            import scp
            with scp.SCPClient(self.ssh_client.get_transport()) as scp_client:
                for url in nebplatforms:
                    tarball_name = os.path.basename(url)
                    scp_client.put(tarball_name, '/tmp/' + tarball_name)
                    logging.info(f"Transferred {tarball_name} to {self.config['hosts'][host]['address']}/tmp/")
            self.extract_tarballs()
            #self.check_ping(self.config['hosts'][host]['address'])

            timestamp = time.strftime("%Y%m%d%H%M%S")
            temp_dir = self.create_temp_directory(timestamp)
            self.scp_to_temp_directory(os.path.join(os.getcwd(), 'payload', 'nebula.service'), temp_dir)
            self.copy_to_target_location(temp_dir, self.config['etcdir'])
            self.set_permissions(self.config['etcdir'], {'owner': 'nobody', 'mode': '755'})

            logging.info(f"Finished setup for host: {host}")

    def execute_commands(self, commands):
        if self.active_host.get('sudo', False): 
            use_sudo = True
        else: 
            use_sudo = False
        sudo_prefix = "sudo " if use_sudo else ""
        for command in commands:
            logging.debug(f"Executing command: {sudo_prefix + command}")
            try:
                if use_sudo:
                    channel = self.ssh_client.invoke_shell()
                    time.sleep(1)
                    channel.send(sudo_prefix + command + '\n')
                    time.sleep(1)
                    if channel.recv_ready():
                        output = channel.recv(1024).decode()
                        if 'password' in output.lower():
                            channel.send(self.active_host['password'] + '\n')  # Send password
                            time.sleep(1)
                        while channel.recv_ready():
                            channel.recv(1024)  # discard output
                            time.sleep(0.1)
                else:
                    stdin, stdout, stderr = self.ssh_client.exec_command(sudo_prefix + command)
                    out = stdout.read().decode()
                    err = stderr.read().decode()
                    if out:
                        logging.info(f"Command output: {out}")
                    if err:
                        logging.error(f"Command error: {err}")
                        print(f"Command: {sudo_prefix + command}")
                        print(f"Command error: {err}")
                        raise Exception(f"Command execution failed: {command}, Error: {err}")
            except Exception as e:
                logging.error(f"Error executing command: {command}, Exception: {e}")
                raise

    def create_temp_directory(self, timestamp):
        temp_dir = f"/tmp/{timestamp}-nebdeploy"
        self.execute_commands([f"mkdir -p {temp_dir}"])
        logging.info(f"Created temporary directory: {temp_dir}")
        self.set_permissions(temp_dir, { "owner":self.active_host["username"], "mode": 777 } )
        return temp_dir

    def scp_to_temp_directory(self, filename, temp_dir):
        import scp
        with scp.SCPClient(self.ssh_client.get_transport()) as scp_client:
            scp_client.put(filename, f"{temp_dir}/{os.path.basename(filename)}")
            logging.info(f"Transferred {filename} to {temp_dir}/")

    def copy_to_target_location(self, temp_dir, target_path):
        commands = [
            f"cp {temp_dir}/* {target_path}/"
        ]
        self.execute_commands(commands)

    def set_permissions(self, target_path, permissions):
        commands = [
            f"chown {permissions['owner']} {target_path}",
            f"chmod {permissions['mode']} {target_path}"
        ]
        self.execute_commands(commands)

    def removetmpdirs(self):
        logging.info(f"Checking for existing nebdeploy directories on {self.active_host['name']}...")
        check_command = "ls /tmp/*-nebdeploy 2>/dev/null"
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(check_command)
            existing_dirs = stdout.read().decode().strip()
            
            if existing_dirs:
                logging.info(f"Found existing nebdeploy directories: {existing_dirs}. Removing...")
                command = "rm -rf /tmp/*-nebdeploy"
                self.execute_commands([command])
                logging.info(f"Removed nebdeploy directories from {self.active_host['name']}.")
            else:
                logging.info(f"No nebdeploy directories found on {self.active_host['name']}. Skipping removal.")
        except Exception as e:
            logging.error(f"Error checking/removing tmp dirs: {e}")
            raise

    def check_distribution(self):
        try:
            command = "uname"
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            os_name = stdout.read().decode().strip().lower()
            if os_name not in supported_os:
                logging.error(f"OS Unsupported: {os_name}")
                print(f"OS Unsupported: {os_name}")
                sys.exit(1)
            if os_name == "linux":
                command = "grep '^ID=' /etc/os-release | awk -F= '{print $2}'"
                stdin, stdout, stderr = self.ssh_client.exec_command(command)
                distro = stdout.read().decode().strip().lower()
                if distro != "ubuntu":
                    logging.error("Distro Unsupported")
                    print("Distro Unsupported")
                    sys.exit(1)
        except Exception as e:
            logging.error(f"Error checking distribution: {e}")
            raise

    def download_file(self, url, dest):
        if os.path.exists(dest):
            logging.info(f"File already exists: {dest}. Skipping download.")
            return  # Early return if the file exists

        logging.debug(f"Starting download from {url} to {dest}...")
        try:
            import requests
            response = requests.get(url, stream=True)
            response.raise_for_status()  # Raise an error for bad responses
            
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

    def create_directories(self):
        commands = [
            "mkdir -p /opt/nebula/bin",
            "mkdir -p /opt/nebula/etc"
        ]
        self.execute_commands(commands)

    def extract_tarballs(self):
        commands = [
            "tar -xzf /tmp/nebula-linux-amd64.tar.gz -C /opt/nebula/bin",
            "tar -xzf /tmp/nebula-freebsd-amd64.tar.gz -C /opt/nebula/bin"
        ]
        self.execute_commands(commands)

    def check_ping(self, address):
        response = os.system(f"ping -c 1 {address}")
        if response != 0:
            logging.warning(f"Host {address} is not reachable.")
            print(f"Host {address} is not reachable.")
        else:
            logging.info(f"Host {address} is reachable.")
            print(f"Host {address} is reachable.")

    def deploy_rclocal(self):
        import scp
        with scp.SCPClient(self.ssh_client.get_transport()) as scp_client:
            scp_client.put(os.path.join(os.getcwd(), 'payload', 'startup_rclocal.py'), '/opt/nebula/startup_rclocal.py')
        self.execute_commands(["python3 /opt/nebula/startup_rclocal.py"])

    def distribute_certificates(self):
        # Logic for generating and distributing certificates
        pass

    def deploy_config(self, etcdir):
        import scp
        with scp.SCPClient(self.ssh_client.get_transport()) as scp_client:
            scp_client.put('path/to/nebula.yml', f'{etcdir}/nebula.yml')

    def start_nebula_service(self, address):
        # Logic to start the Nebula service and check connectivity
        pass

    def validate_installation(self):
        logging.info("Validating installation...")
        bindir = self.config['bindir']
        etcdir = self.config['etcdir']

        def check_path(path, mode, owner):
            if not os.path.exists(path):
                logging.error(f"{path} does not exist.")
                return False
            stat_info = os.stat(path)
            if stat_info.st_mode & 0o777 != mode:
                logging.error(f"{path} does not have the correct permissions.")
                return False
            if stat_info.st_uid != 0:  # Check if owned by root (UID 0)
                logging.error(f"{path} is not owned by root.")
                return False
            return True

        # Check bindir
        if not check_path(bindir, 0o755, 0):
            raise Exception(f"Validation failed for bindir: {bindir}")

        # Check etcdir
        if not check_path(etcdir, 0o755, 0):
            raise Exception(f"Validation failed for etcdir: {etcdir}")

        # Check binaries
        binaries = [f"{bindir}/nebula", f"{bindir}/nebula-cert"]
        for binary in binaries:
            if not check_path(binary, 0o755, 0):
                raise Exception(f"Validation failed for binary: {binary}")

        # Check config file
        config_file = f"{etcdir}/config.yml"
        if not check_path(config_file, 0o600, 0):
            raise Exception(f"Validation failed for config file: {config_file}")

        logging.info("Installation validation successful.")
    
if __name__ == "__main__":
    deploy_util = NebulaDeployUtil('config.json')

    # Get arguments
    parser = argparse.ArgumentParser(description='Nebula Deployment Script')
    parser.add_argument('--remove', action='store_true', help='Remove Nebula from all hosts')
    args = parser.parse_args()
    
    # Check to make sure we have the credentials to act
    deploy_util.ensure_credentials()

    # Determine which mode to operate in
    if args.remove:
        deploy_util.uninstall()
    else:
        deploy_util.install()
        deploy_util.validate_installation()
