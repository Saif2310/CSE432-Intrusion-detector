import re
from typing import Set, Dict, Tuple
from enum import Enum

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
    SELECT = 15
    # Stacked query states: ;?\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)
    SEMICOLON = 16
    SPACE_KEYWORD = 17
    KEYWORD = 18

class SQLInjectionFSM:
    def __init__(self):
        # Current states (for non-deterministic simulation)
        self.current_states: Set[State] = {State.START}
        # Accepting states
        self.accepting_states: Set[State] = {
            State.VALUE2,  # Tautology complete
            State.COMMENT, # -- or /*
            State.SELECT,  # UNION SELECT
            State.KEYWORD  # Stacked query keyword
        }
        # Character classes
        self.word_chars = set('abcdefghijklmnopqrstuvwxyz0123456789_')
        self.space_chars = set(' \t\n')
        self.digit_chars = set('0123456789')
        self.keywords = {'select', 'insert', 'update', 'delete', 'drop', 'alter', 'create'}

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
                    next_states.add(State.SPACE_OR_AND)  # Skip quotes directly to OR/AND
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
                    next_states.add(State.AND)  # Stay for 'nd'
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
                next_states.add(State.START)
            elif state == State.SPACE_KEYWORD:
                if char in self.space_chars:
                    next_states.add(State.SPACE_KEYWORD)
                elif char in {'s', 'i', 'u', 'd', 'a', 'c'}:
                    next_states.add(State.KEYWORD)
                next_states.add(State.START)
            elif state == State.KEYWORD:
                if char in self.word_chars:
                    next_states.add(State.KEYWORD)
                next_states.add(State.START)

        self.current_states = next_states

    def is_accepted(self) -> bool:
        """Check if any current state is accepting."""
        return bool(self.current_states & self.accepting_states)

    def reset(self):
        """Reset FSM to initial state."""
        self.current_states = {State.START}

def scan_http_request(http_body: str) -> bool:
    """Scan HTTP request body for SQL injection patterns."""
    fsm = SQLInjectionFSM()
    for char in http_body:
        fsm.transition(char)
        if fsm.is_accepted():
            return True  # Attack detected
    return False  # No attack detected

# Example usage
if __name__ == "__main__":
    # Example HTTP request bodies
    test_cases = [
        # Malicious: Tautology
        "username=admin&password=' OR '1'='1",
        # Malicious: Comment
        "id=1'--",
        # Malicious: UNION
        "id=1' UNION SELECT username, password FROM users--",
        # Malicious: Stacked query
        "email=test@ex.com'; DROP TABLE users; --",
        # Legitimate: Contains 'select' but not an attack
        "description=Please select an option"
    ]

    for i, body in enumerate(test_cases):
        result = scan_http_request(body)
        print(f"Test {i+1}: {body}")
        print(f"Attack detected: {result}\n")
