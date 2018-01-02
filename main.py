import os
import argparse
import logging

from lib.core import ROOT_DIR
from lib.core import Classifier, Analyser, Scheduler

log = logging.getLogger()

def init_logging(clog_level):
    """ Configuring the root logger.
        We will log to to the logging file `main.log` with level logging.DEBUG
        by default.
    Args:
        clog_level: logging level (int)
    """
    formatter = logging.Formatter('%(asctime)s - %(module)s - %(levelname)s - %(message)s')
    log.setLevel(logging.DEBUG)
    log_file = os.path.join(ROOT_DIR, 'log', 'main.log')
    file_logger = logging.FileHandler(log_file)
    file_logger.setFormatter(formatter)
    file_logger.setLevel(logging.DEBUG)
    console_logger = logging.StreamHandler()
    console_logger.setFormatter(formatter)
    console_logger.setLevel(clog_level)
    log.addHandler(console_logger)
    log.addHandler(file_logger)

def walk_directory(dir_path):
    """ Given a directory return the list of all files
        in that directory
    Args:
        dir_path: string that hold the fullpath to a directory
    Returns:
        A list of all the files in the directory.
    Raises:
        IOError if the path does not exist.
        TypeError if dir_path is not string.
    """
    log.debug('Walking dir: %s', dir_path)
    if not isinstance(dir_path, str):
        raise TypeError('Invalid dir_path value. Must be string.')
    if not os.path.exists(dir_path):
        raise IOError('Could not find dir_path.')
    file_paths = []
    for root, _, files in os.walk(dir_path):
        for file_name in files:
            file_paths.append(os.path.join(root, file_name))
    return file_paths

def main():

    parser = argparse.ArgumentParser('Rule Creator')
    parser.add_argument('input', help='File or directory to create yara rules for')
    parser.add_argument('-d', '--dir', action='store_true', help='Specify if input is a directory of similar files')
    parser.add_argument('-a', '--aggr', action='store_true', help='Specify whether to aggregate into one rule')
    parser.add_argument('-l', '--log', choices=['error', 'info', 'debug'], help='define the logging level to be used.')

    options = parser.parse_args()

    full_path = os.path.abspath(options.input)
    if options.dir:
        scan_files = walk_directory(full_path)
    else:
        scan_files = []
        scan_files.append(full_path)
    if options.log:
        log_level = getattr(logging, options.log.upper())
        if not isinstance(log_level, int):
            raise ValueError('Invalid log level: %s' % log_level)
    else:
        log_level = logging.INFO
    

    init_logging(log_level)
    if options.aggr:
        pipeline = Scheduler()
    else:
        pipeline = Scheduler()
        
    for scan_file in scan_files:
        pipeline.add_task(scan_file)
        # Depending on the type of the file 
        # the scheduler should invoke an appropriate analyser
    pipeline.process()


if __name__ == "__main__":
    main()