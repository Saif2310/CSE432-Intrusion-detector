from flask import Flask, request, jsonify
from intrusion_detection import SQLInjectionFSM, scan_http_request
from flask_cors import CORS  


app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

@app.route('/check-sql-injection', methods=['POST'])
def check_sqli():
    try:
        data = request.get_json()
        http_request = data.get('http_request', '')
        print(f"Received request to scan: {http_request[:100]}...")  
        
        is_malicious = scan_http_request(http_request)
        print(f"Detection result: {is_malicious}")  
        
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