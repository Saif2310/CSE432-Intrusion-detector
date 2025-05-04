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
sql-injection-fsm/
│
├── app.py 
├── index.html 
├── intrusion_detection.py 
├── README.md  


---

## 🛠 How to Run

1. **Make sure Python is installed** (preferably version 3.6 or above).

2. pip install flask
3. pip install flask-cors
