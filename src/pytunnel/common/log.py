import logging

def log_sent(label, message=""):
    logging.debug(f"[ SENT ] {label} {message}")

def log_received(label, message=""):
    logging.debug(f"[ RECV ] {label} {message}")

def log_info(message):
    logging.info(f"[ INFO ] {message}")

def log_error(message):
    logging.error(f"[ ERROR ] {message}")
