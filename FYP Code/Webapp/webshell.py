from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import paramiko
from threading import Thread

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
socketio = SocketIO(app)

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
                socketio.emit('output', {'data': data})
    thread = Thread(target=run)
    thread.start()




@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    if not ssh_client:
        connect_ssh()

@socketio.on('disconnect')
def handle_disconnect():
    global ssh_client, channel
    if ssh_client:
        ssh_client.close()
        ssh_client = None
        channel = None

@socketio.on('input')
def handle_input(data):
    command = data['command']
    if channel:
        channel.send(command + '\n')

if __name__ == '__main__':
    socketio.run(app, debug=True)
