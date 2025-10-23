class Color:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'

def log_sent(label, message=""):
    print(f"{Color.YELLOW}[ SENT ]{Color.END} {label} {message}")

def log_received(label, message=""):
    print(f"{Color.GREEN}[ RECV ]{Color.END} {label} {message}")

def log_info(message):
    print(f"{Color.BLUE}[ INFO ]{Color.END} {message}")

def log_error(message):
    print(f"{Color.RED}[ ERROR ]{Color.END} {message}")
