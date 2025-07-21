import logging

def setup_logging():
    """Configure logging for rabbitRecon"""
    logger = logging.getLogger('rabbitRecon')
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger
