#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import shutil
import threading
import tempfile
import subprocess
import re
import paramiko
from paramiko import SSHClient
from scp import SCPClient
from tqdm import tqdm
import traceback
import argparse
import frida

# Constants
USER = 'root'
PASSWORD = 'alpine'
HOSTNAME = 'localhost'
PORT = 2222
KEY_FILENAME = None

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
DUMP_JS = os.path.join(SCRIPT_DIR, 'dump.js')
TEMP_DIR = tempfile.gettempdir()
PAYLOAD_DIR = 'Payload'
PAYLOAD_PATH = os.path.join(TEMP_DIR, PAYLOAD_DIR)
FILE_DICT = {}

FINISHED = threading.Event()


def get_usb_iphone():
    """Detect USB iPhone using Frida."""
    device_manager = frida.get_device_manager()
    device = None
    device_type = 'usb' if int(frida.__version__.split('.')[0]) >= 12 else 'tether'
    
    while device is None:
        devices = [dev for dev in device_manager.enumerate_devices() if dev.type == device_type]
        if not devices:
            print('Waiting for USB device...')
            FINISHED.wait()
        else:
            device = devices[0]
    
    return device


def generate_ipa(path, display_name):
    """Generate IPA from the dumped app."""
    ipa_filename = f'{display_name}.ipa'
    print(f'Generating "{ipa_filename}"')
    
    try:
        app_name = FILE_DICT['app']
        
        for key, value in FILE_DICT.items():
            src = os.path.join(path, key)
            dest = os.path.join(path, app_name, value)
            if key != 'app':
                shutil.move(src, dest)
        
        zip_args = ('zip', '-qr', os.path.join(os.getcwd(), ipa_filename), PAYLOAD_DIR)
        subprocess.check_call(zip_args, cwd=TEMP_DIR)
        shutil.rmtree(PAYLOAD_PATH)
    except Exception as e:
        print(f"Error generating IPA: {e}")
        FINISHED.set()


def on_message(message, data):
    """Handle messages received from Frida script."""
    t = tqdm(unit='B', unit_scale=True, unit_divisor=1024, miniters=1)
    last_sent = [0]

    def progress(filename, size, sent):
        base_name = os.path.basename(filename)
        t.desc = base_name
        t.total = size
        t.update(sent - last_sent[0])
        last_sent[0] = 0 if size == sent else sent

    if 'payload' in message:
        payload = message['payload']
        if 'dump' in payload:
            scp_transfer(payload['dump'], PAYLOAD_PATH)
            FILE_DICT[os.path.basename(payload['dump'])] = extract_path(payload['path'])
        
        if 'app' in payload:
            scp_transfer(payload['app'], PAYLOAD_PATH, recursive=True)
            FILE_DICT['app'] = os.path.basename(payload['app'])
        
        if 'done' in payload:
            FINISHED.set()
    
    t.close()


def scp_transfer(src, dest, recursive=False):
    """Transfer files via SCP."""
    try:
        print(f"Transferring {src} to {dest} via SCP")
        with SCPClient(ssh.get_transport(), progress=progress_bar, socket_timeout=60) as scp:
            scp.get(src, dest, recursive=recursive)

        # Check if the file exists before attempting to chmod
        base_name = os.path.basename(src).decode('utf-8') if isinstance(src, bytes) else src
        dest_path = os.path.join(dest, base_name)

        if os.path.exists(dest_path):
            print(f"Changing permissions for {dest_path}")
            chmod_args = ('chmod', '755', dest_path)
            subprocess.check_call(chmod_args)
    except subprocess.CalledProcessError as err:
        print(f"Error setting file permissions: {err}")
    except Exception as e:
        print(f"Error during SCP transfer: {e}")




def progress_bar(filename, size, sent):
    """Display progress for SCP transfer."""
    base_name = os.path.basename(filename.decode('utf-8') if isinstance(filename, bytes) else filename)
    t = tqdm(unit='B', unit_scale=True, unit_divisor=1024, miniters=1)
    t.desc = base_name
    t.total = size
    t.update(sent)


def extract_path(origin_path):
    """Extract the relative path for the dumped app."""
    index = origin_path.find('.app/')
    return origin_path[index + 5:]


def open_target_app(device, app_id):
    """Open the target app on the device."""
    print(f'Starting app {app_id}')
    pid, session, display_name, bundle_identifier = '', None, '', ''
    
    for app in get_applications(device):
        if app_id == app.identifier or app_id == app.name:
            pid, display_name, bundle_identifier = app.pid, app.name, app.identifier
    
    try:
        if not pid:
            pid = device.spawn([bundle_identifier])
            session = device.attach(pid)
            device.resume(pid)
        else:
            session = device.attach(pid)
    except Exception as e:
        print(f"Error starting app: {e}")
    
    return session, display_name, bundle_identifier


def start_dump(session, ipa_name):
    """Start the dumping process."""
    print(f'Dumping {ipa_name} to {TEMP_DIR}')
    script = load_js_file(session, DUMP_JS)
    script.post('dump')
    FINISHED.wait()
    generate_ipa(PAYLOAD_PATH, ipa_name)
    if session:
        session.detach()


def load_js_file(session, filename):
    """Load and execute a JavaScript file in a Frida session."""
    with open(filename, 'r', encoding='utf-8') as f:
        source = f.read()
    
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()
    return script


def get_applications(device):
    """Retrieve the list of applications on the device."""
    try:
        return device.enumerate_applications()
    except Exception as e:
        sys.exit(f'Failed to enumerate applications: {e}')


def list_applications(device):
    """List all installed applications."""
    apps = get_applications(device)
    if apps:
        pid_width = max(len(str(app.pid)) for app in apps)
        name_width = max(len(app.name) for app in apps)
        id_width = max(len(app.identifier)) if apps else 0
        print(f'{"PID":>{pid_width}}  {"Name":<{name_width}}  {"Identifier":<{id_width}}')
        print(f'{"-"*pid_width}  {"-"*name_width}  {"-"*id_width}')
        for app in apps:
            pid_display = '-' if app.pid == 0 else str(app.pid)
            print(f'{pid_display:>{pid_width}}  {app.name:<{name_width}}  {app.identifier:<{id_width}}')
    else:
        print('No applications found.')


def create_dir(path):
    """Create a directory if it doesn't exist, or clear it if it does."""
    path = path.rstrip('\\')
    if os.path.exists(path):
        shutil.rmtree(path)
    try:
        os.makedirs(path)
    except os.error as err:
        print(f"Error creating directory: {err}")


def main():
    parser = argparse.ArgumentParser(description='frida-ios-dump (by AloneMonkey v2.0)')
    parser.add_argument('-l', '--list', action='store_true', help='List installed apps')
    parser.add_argument('-o', '--output', help='Specify output IPA filename')
    parser.add_argument('-H', '--hostname', help='SSH hostname')
    parser.add_argument('-p', '--port', help='SSH port')
    parser.add_argument('-u', '--user', help='SSH username')
    parser.add_argument('-P', '--password', help='SSH password')
    parser.add_argument('-K', '--key_filename', help='SSH private key file path')
    parser.add_argument('target', nargs='?', help='Bundle identifier or display name of target app')

    args = parser.parse_args()

    if not sys.argv[1:]:
        parser.print_help()
        sys.exit(1)

    device = get_usb_iphone()

    if args.list:
        list_applications(device)
    else:
        try:
            global ssh
            ssh = SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=args.hostname or HOSTNAME, 
                port=int(args.port or PORT), 
                username=args.user or USER, 
                password=args.password or PASSWORD, 
                key_filename=args.key_filename or KEY_FILENAME
            )

            create_dir(PAYLOAD_PATH)
            session, display_name, bundle_identifier = open_target_app(device, args.target)
            if session:
                output_ipa = args.output if args.output else display_name
                start_dump(session, output_ipa)
        except Exception as e:
            print(f"Error: {e}")
            traceback.print_exc()

    FINISHED.set()
    ssh.close()


if __name__ == '__main__':
    main()
