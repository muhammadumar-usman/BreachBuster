import paramiko
from threading import Thread
import time

# Preset SSH credentials
VM_ADDRESS = '192.168.61.129'
USERNAME = 'umar'
PASSWORD = 'kali'

ssh_client = None
channel = None

def connect_ssh():
    global ssh_client, channel
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(VM_ADDRESS, username=USERNAME, password=PASSWORD)
    channel = ssh_client.invoke_shell()
    listen_to_channel()

def listen_to_channel():
    def run():
        while True:
            if channel.recv_ready():
                data = channel.recv(1024).decode('utf-8')
                time.sleep(0.3)  # Wait for 0.3 seconds
                print(data.split('>')[-1].strip())
    thread = Thread(target=run)
    thread.start()

if __name__ == '__main__':
    connect_ssh()
