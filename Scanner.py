import re
from typing import Set, Dict, Tuple
from enum import Enum
from urllib.parse import parse_qs, urlparse
import json

class State(Enum):
    # Initial state
    START = 0
    # Tautology states: '*\s*(OR|AND)\s*('?\w+'?|\d+)\s*=\s*('?\w+'?|\d+)
    QUOTE = 1
    SPACE_OR_AND = 2
    OR = 3
    AND = 4
    VALUE1 = 5
    EQUALS = 6
    VALUE2 = 7
    # Comment states: (--|/\*)
    DASH = 8
    COMMENT = 9
    SLASH = 10
    # UNION states: UNION\s+(ALL\s+)?SELECT
    UNION = 11
    UNION_SPACE = 12
    ALL = 13
    ALL_SPACE = 14
    COLORS = 15
    # Stacked query states: ;?\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)
    SEMICOLON = 16
    SPACE_KEYWORD = 17
    KEYWORD = 18
    KEYWORD_CONFIRM = 19  # Confirm keyword is followed by space and word

class SQLInjectionFSM:
    def __init__(self):
        # Current states
        self.current_states: Set[State] = {State.START}
        # Accepting states
        self.accepting_states: Set[State] = {
            State.VALUE2,  # Tautology complete
            State.COMMENT, # -- or /*
            State.SELECT,  # UNION SELECT
            State.KEYWORD_CONFIRM  # Stacked query keyword with context
        }
        # Character classes
        self.word_chars = set('abcdefghijklmnopqrstuvwxyz0123456789_')
        self.space_chars = set(' \t\n')
        self.digit_chars = set('0123456789')
        self.keywords = {'select', 'insert', 'update', 'delete', 'drop', 'alter', 'create'}
        # Track current keyword being built
        self.current_keyword = ''

    def transition(self, char: str) -> None:
        """Update current states based on input character."""
        next_states: Set[State] = set()
        char = char.lower()  # Case-insensitive matching

        for state in self.current_states:
            if state == State.START:
                if char == "'":
                    next_states.add(State.QUOTE)
                if char == '-':
                    next_states.add(State.DASH)
                if char == '/':
                    next_states.add(State.SLASH)
                if char == 'u':
                    next_states.add(State.UNION)
                if char == ';':
                    next_states.add(State.SEMICOLON)
                next_states.add(State.START)
            elif state == State.QUOTE:
                if char == "'":
                    next_states.add(State.QUOTE)
                elif char in self.space_chars:
                    next_states.add(State.SPACE_OR_AND)
                else:
                    next_states.add(State.SPACE_OR_AND)
                next_states.add(State.START)
            elif state == State.SPACE_OR_AND:
                if char in self.space_chars:
                    next_states.add(State.SPACE_OR_AND)
                elif char == 'o':
                    next_states.add(State.OR)
                elif char == 'a':
                    next_states.add(State.AND)
                next_states.add(State.START)
            elif state == State.OR:
                if char == 'r':
                    next_states.add(State.VALUE1)
                next_states.add(State.START)
            elif state == State.AND:
                if char == 'n':
                    next_states.add(State.AND)
                elif char == 'd' and State.AND in self.current_states:
                    next_states.add(State.VALUE1)
                next_states.add(State.START)
            elif state == State.VALUE1:
                if char in self.word_chars or char in self.digit_chars:
                    next_states.add(State.VALUE1)
                elif char == "'":
                    next_states.add(State.VALUE1)
                elif char in self.space_chars:
                    next_states.add(State.EQUALS)
                elif char == '=':
                    next_states.add(State.EQUALS)
                next_states.add(State.START)
            elif state == State.EQUALS:
                if char in self.space_chars:
                    next_states.add(State.EQUALS)
                elif char in self.word_chars or char in self.digit_chars:
                    next_states.add(State.VALUE2)
                elif char == "'":
                    next_states.add(State.VALUE2)
                next_states.add(State.START)
            elif state == State.VALUE2:
                if char in self.word_chars or char in self.digit_chars:
                    next_states.add(State.VALUE2)
                elif char == "'":
                    next_states.add(State.VALUE2)
                next_states.add(State.START)
            elif state == State.DASH:
                if char == '-':
                    next_states.add(State.COMMENT)
                next_states.add(State.START)
            elif state == State.SLASH:
                if char == '*':
                    next_states.add(State.COMMENT)
                next_states.add(State.START)
            elif state == State.UNION:
                if char == 'n':
                    next_states.add(State.UNION)
                elif char == 'i' and State.UNION in self.current_states:
                    next_states.add(State.UNION)
                elif char == 'o' and State.UNION in self.current_states:
                    next_states.add(State.UNION)
                elif char == 'n' and State.UNION in self.current_states:
                    next_states.add(State.UNION_SPACE)
                next_states.add(State.START)
            elif state == State.UNION_SPACE:
                if char in self.space_chars:
                    next_states.add(State.UNION_SPACE)
                elif char == 'a':
                    next_states.add(State.ALL)
                elif char == 's':
                    next_states.add(State.SELECT)
                next_states.add(State.START)
            elif state == State.ALL:
                if char == 'l':
                    next_states.add(State.ALL)
                elif char == 'l' and State.ALL in self.current_states:
                    next_states.add(State.ALL_SPACE)
                next_states.add(State.START)
            elif state == State.ALL_SPACE:
                if char in self.space_chars:
                    next_states.add(State.ALL_SPACE)
                elif char == 's':
                    next_states.add(State.SELECT)
                next_states.add(State.START)
            elif state == State.SELECT:
                if char in {'e', 'l', 'c', 't'}:
                    next_states.add(State.SELECT)
                next_states.add(State.START)
            elif state == State.SEMICOLON:
                if char in self.space_chars:
                    next_states.add(State.SPACE_KEYWORD)
                elif char in {'s', 'i', 'u', 'd', 'a', 'c'}:
                    next_states.add(State.KEYWORD)
                    self.current_keyword = char
                next_states.add(State.START)
            elif state == State.SPACE_KEYWORD:
                if char in self.space_chars:
                    next_states.add(State.SPACE_KEYWORD)
                elif char in {'s', 'i', 'u', 'd', 'a', 'c'}:
                    next_states.add(State.KEYWORD)
                    self.current_keyword = char
                next_states.add(State.START)
            elif state == State.KEYWORD:
                if char in self.word_chars:
                    self.current_keyword += char
                    if self.current_keyword in self.keywords:
                        next_states.add(State.KEYWORD_CONFIRM)
                    else:
                        next_states.add(State.KEYWORD)
                next_states.add(State.START)
            elif state == State.KEYWORD_CONFIRM:
                if char in self.space_chars:
                    next_states.add(State.KEYWORD_CONFIRM)
                elif char in self.word_chars:
                    next_states.add(State.KEYWORD_CONFIRM)  # Accept as part of query
                next_states.add(State.START)

        self.current_states = next_states

    def is_accepted(self) -> bool:
        """Check if any current state is accepting."""
        return bool(self.current_states & self.accepting_states)

    def reset(self):
        """Reset FSM to initial state."""
        self.current_states = {State.START}
        self.current_keyword = ''

def parse_http_request(http_request: str) -> list:
    """Parse an HTTP request and extract parts to inspect for SQL injection."""
    parts_to_scan = []
    
    # Split request into headers and body
    try:
        headers, body = http_request.split('\n\n', 1) if '\n\n' in http_request else (http_request, '')
    except ValueError:
        headers, body = http_request, ''
    
    # Parse headers
    header_lines = headers.split('\n')
    request_line = header_lines[0]
    
    # Extract query parameters from URL (GET requests)
    if ' ' in request_line:
        method, url, _ = request_line.split(' ', 2)
        parsed_url = urlparse(url)
        query_string = parsed_url.query
        if query_string:
            parts_to_scan.append(query_string)
            # Parse query string into key-value pairs
            query_params = parse_qs(query_string)
            for key, values in query_params.items():
                parts_to_scan.extend(values)
    
    # Extract body (POST requests)
    if body:
        # Handle application/x-www-form-urlencoded
        if 'Content-Type: application/x-www-form-urlencoded' in headers:
            parts_to_scan.append(body)
            # Parse body into key-value pairs
            body_params = parse_qs(body)
            for key, values in body_params.items():
                parts_to_scan.extend(values)
        # Handle application/json
        elif 'Content-Type: application/json' in headers:
            try:
                json_data = json.loads(body)
                # Extract all string values from JSON
                def extract_strings(data):
                    if isinstance(data, str):
                        return [data]
                    elif isinstance(data, dict):
                        return [s for value in data.values() for s in extract_strings(value)]
                    elif isinstance(data, list):
                        return [s for item in data for s in extract_strings(item)]
                    return []
                parts_to_scan.extend(extract_strings(json_data))
            except json.JSONDecodeError:
                pass
    
    # Extract cookies
    for line in header_lines:
        if line.lower().startswith('cookie:'):
            cookie_str = line[len('Cookie:'):].strip()
            cookies = cookie_str.split(';')
            for cookie in cookies:
                if '=' in cookie:
                    _, value = cookie.split('=', 1)
                    parts_to_scan.append(value.strip())
    
    # Extract specific headers (e.g., User-Agent, Referer)
    for line in header_lines:
        if line.lower().startswith(('user-agent:', 'referer:')):
            _, value = line.split(':', 1)
            parts_to_scan.append(value.strip())
    
    return parts_to_scan

def scan_http_request(http_request: str) -> bool:
    """Scan HTTP request for SQL injection patterns."""
    # Normalize input: decode URL-encoded characters
    def normalize(text):
        return re.sub(r'%27', "'", re.sub(r'%20', " ", text))
    
    # Parse request to get parts to scan
    parts = parse_http_request(http_request)
    
    # Initialize FSM
    fsm = SQLInjectionFSM()
    
    # Scan each part
    for part in parts:
        normalized_part = normalize(part)
        for char in normalized_part:
            fsm.transition(char)
            if fsm.is_accepted():
                print(f"Attack detected in: {part}")
                return True  # Attack detected
        fsm.reset()  # Reset FSM for next part
    
    return False  # No attack detected

# Example usage
if __name__ == "__main__":
    # Example HTTP requests
    test_cases = [
        # Malicious: Tautology in POST body
        """POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 36

username=admin&password=' OR '1'='1""",
        # Malicious: Comment in query parameter
        """GET /search?id=1'-- HTTP/1.1
Host: example.com""",
        # Malicious: UNION in query parameter
        """GET /search?id=1' UNION SELECT username, password FROM users-- HTTP/1.1
Host: example.com""",
        # Malicious: Stacked query in JSON body
        """POST /api/update HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 44

{"email": "test@ex.com'; DROP TABLE users; --"}""",
        # Legitimate: Contains 'select' in body
        """POST /submit HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

description=Please select an option""",
        # Malicious: Injection in cookie
        """GET /profile HTTP/1.1
Host: example.com
Cookie: session=abc' OR '1'='1""",
    ]

    for i, request in enumerate(test_cases):
        result = scan_http_request(request)
        print(f"Test {i+1}:")
        print(request)
        print(f"Attack detected: {result}\n")
