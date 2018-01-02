import logging

from lib.core import Analyser

log = logging.getLogger(__name__)

class JPEG(Analyser):
    def run(self):
        log.debug('Running %s analyser', __name__)