from flask import Flask, render_template, request, redirect, url_for, flash
import nmap

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan_network():
    # Perform a network scan using Nmap
    scanner = nmap.PortScanner()
    scanner.scan(hosts='192.168.1.0/24', arguments='-F')  # Example IP range, adjust as needed

    # Extract scan results
    devices = []
    for host in scanner.all_hosts():
        devices.append({
            'ip': host,
            'mac': scanner[host]['addresses']['mac'],
            'status': scanner[host]['status']['state']
        })

    return render_template('scan.html', devices=devices)

if __name__ == '__main__':
    app.run(debug=True)
