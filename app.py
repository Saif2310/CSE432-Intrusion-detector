from flask import Flask, request, jsonify
from flask_cors import CORS  # Add this import
from intrusion_detection import SQLInjectionFSM, scan_http_request

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

@app.route('/check-sql-injection', methods=['POST'])
def check_sqli():
    try:
        data = request.get_json()
        http_request = data.get('http_request', '')
        print(f"Received request to scan: {http_request[:100]}...")  # Debug print
        
        is_malicious = scan_http_request(http_request)
        print(f"Detection result: {is_malicious}")  # Debug print
        
        return jsonify({
            "is_malicious": is_malicious,
            "status": "success"
        })
    except Exception as e:
        print(f"Error processing request: {str(e)}")
        return jsonify({
            "is_malicious": False,
            "status": "error",
            "message": str(e)
        }), 500

if __name__ == '__main__':
    app.run(port=5000, debug=True)