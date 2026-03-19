"""
Logger - Structured logging with file output
"""

import logging
import os
from datetime import datetime

os.makedirs('logs', exist_ok=True)

# Add SUCCESS level
SUCCESS_LEVEL = 25
logging.addLevelName(SUCCESS_LEVEL, 'SUCCESS')


def success(self, message, *args, **kwargs):
    if self.isEnabledFor(SUCCESS_LEVEL):
        self._log(SUCCESS_LEVEL, message, args, **kwargs)


logging.Logger.success = success

_logger = None


def setup_logger(verbose=False, silent=False):
    global _logger
    logger = logging.getLogger('m7smartssrf')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    # Console handler
    if not silent:
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG if verbose else logging.INFO)

        class ColorFormatter(logging.Formatter):
            COLORS = {
                'DEBUG':   '\033[90m',
                'INFO':    '\033[0m',
                'WARNING': '\033[33m',
                'ERROR':   '\033[31m',
                'SUCCESS': '\033[32m',
            }
            RESET = '\033[0m'

            def format(self, record):
                color = self.COLORS.get(record.levelname, '')
                return f"{color}{record.getMessage()}{self.RESET}"

        ch.setFormatter(ColorFormatter())
        logger.addHandler(ch)

    # File handlers
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    fh = logging.FileHandler(f'logs/scan_{ts}.log')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(fh)

    _logger = logger
    return logger


def get_logger():
    global _logger
    if _logger is None:
        _logger = setup_logger()
    return _logger
