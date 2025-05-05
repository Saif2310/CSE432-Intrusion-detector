# CSE432-Intrusion-detector
# SQL Injection Detection using Finite State Machine (FSM)

This project implements a **Finite State Machine (FSM)** for detecting **SQL injection attacks** in HTTP requests. It parses each HTTP request, extracts user inputs, and identifies potentially malicious patterns using a state-driven approach.

## 🚀 Project Description

SQL Injection is a common web security vulnerability that allows attackers to interfere with the queries that an application makes to its database. This project aims to **detect SQL injection attempts** in HTTP requests by simulating how an FSM processes the input and flags malicious content.

### Key Features

- Parses HTTP GET and POST requests
- Extracts query parameters and body content
- Simulates FSM to detect SQL injection patterns
- Classifies each request as either **malicious** or **clean**
- Designed to be extensible and educational

---

## 🗂 Project Structure

├── app.py 
├── index.html 
├── intrusion_detection.py 
├── README.md  


---

## 🛠 How to Run

Requirements
------------
* Python 3.x
* Flask
* Flask-CORS

Installation
------------

1. Install the required Python packages:
   pip install Flask Flask-CORS

Usage
-----
1. Run the Flask application:
   python app.py
   The server will start at http://127.0.0.1:5000.

2. Open the index.html file in a web browser.

3. Enter an HTTP request in the text area or select a test case from the dropdown.

4. Click the "Test for SQL Injection" button to analyze the request.

5. The result will be displayed below the button, indicating whether an SQL injection attack was detected.

API Endpoint
------------
The system provides an API endpoint for programmatic access:

* Endpoint: http://127.0.0.1:5000/check-sql-injection
* Method: POST
* Request Body (JSON):
  {
      "http_request": "The HTTP request string to analyze"
  }
* Response (JSON):
  {
      "is_malicious": true/false,
      "status": "success/error",
      "message": "Error message (if status is error)"
  }

Files
-----
* app.py:  Flask application that handles the API requests.
* index.html:  HTML file for the user interface.
* intrusion_detection.py:  Python file containing the SQL injection detection logic using the Finite State Machine.

Notes
-----
* The FSM is designed to detect common SQL injection patterns. It may not detect all possible attack variations.
* This system is intended as a first line of defense and should be used in conjunction with other security measures.
* The client-side detection in index.html is a simplified simulation and should not be relied upon for production use. The server-side detection using the FSM is the primary detection mechanism.
