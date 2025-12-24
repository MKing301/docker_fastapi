from loguru import logger

# Remove default logger to avoid duplicate messages
logger.remove()

# Log to console (stdout)
logger.add(lambda msg: print(msg, end=""), level="INFO")

# Log to a file, rotate every 5 MB, keep 7 days of logs
logger.add("logs/app.log", rotation="5 MB", retention="7 days", level="INFO")
