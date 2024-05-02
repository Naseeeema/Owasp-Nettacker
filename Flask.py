from flask import Flask, request, jsonify, send_from_directory
import subprocess
import re  # Import regular expression module

app = Flask(__name__)

@app.route('/')
def index():
    return send_from_directory('static', 'indexx.html')

@app.route('/scan', methods=['POST'])
def scan_endpoint():
    data = request.get_json()
    module = data.get('module')
    target = data.get('target')

    if not module:
        return jsonify({'error': 'Module is required'}), 400

    if not target:
        return jsonify({'error': 'Target URL is required'}), 400

    # Full path to nettacker.py
    nettacker_path = '/home/kali/Nettacker/nettacker.py'

    # Construct the Nettacker command
    command = f"python {nettacker_path} -m {module} -t {target}"

    scan_type = data.get('scan_type')
    if scan_type:
        command += f" -s {scan_type}"

    try:
        # Execute the Nettacker command
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        scan_results = output.decode() if output else error.decode()

        # Parse scan results to extract vulnerabilities
        vulnerabilities = parse_scan_results(scan_results)

        return jsonify({'scan_results': scan_results.strip(), 'vulnerabilities': vulnerabilities})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def parse_scan_results(scan_results):
    # Regular expression pattern to match vulnerabilities
    vulnerability_pattern = r'Vulnerability: (.+)'  # Example pattern, modify as needed

    # Use regular expression to find matches
    matches = re.findall(vulnerability_pattern, scan_results)

    # Return list of vulnerabilities
    return matches

if __name__ == '__main__':
    app.run(debug=True)