import sys
from loguru import logger

def logging_setup():
    """Настройка логгера с цветным выводом, записью в файл и информацией о коде."""
    format_info = (
        "<green>{time:HH:mm:ss.SS}</green> | "
        "<blue>{level}</blue> | "
        "<cyan>{file}</cyan>:<cyan>{line}</cyan> - <yellow>{function}</yellow> | "
        "<level>{message}</level>"
    )
    logger.remove()  # Удаляем стандартный логгер

    # Логирование в консоль с цветным оформлением и уровнем INFO
    logger.add(sys.stdout, colorize=True, format=format_info, level="INFO")

    # Логирование в файл с ротацией (по 50 MB на файл) и компрессией
    logger.add("main.log", rotation="50 MB", compression="zip", format=format_info, level="TRACE")
# Вызов настройки логгирования
logging_setup()