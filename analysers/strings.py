import logging
import re
import os
import json 

from lib.core import Analyser, ROOT_DIR

log = logging.getLogger(__name__)

DEBUG_FILE = os.path.join(ROOT_DIR, 'log', 'strings_extracted.out')

class Strings(Analyser):

    def get_all_strings(self):
        """ Retrieves all strings from a binary blob of data

        Returns:
            ascii_strings: List of ascii strings unescaped
            unicode_strings: List of unicode strings unescaped

        """
        unicode_strings = []
        ascii_strings = []
        ascii_regex = re.compile(rb'[\x20-\x7e]{5,}')
        ascii_raw = ascii_regex.findall(self.data)
        
        unicode_regex = re.compile(rb'(?:[\x20-\x7e][\x00]){5,}')
        unicode_raw = unicode_regex.findall(self.data)
        
        for string in ascii_raw:
            ascii_strings.append(string.decode())

        for string in unicode_raw:
            unicode_strings.append(string.decode('utf16'))

        result = {'ascii': ascii_strings, 'unicode': unicode_strings}
        
        with open(DEBUG_FILE, 'w') as fh:
            fh.write(json.dumps(result))
            
        return result


    def run(self):
        """ Main entry point of the analyser
        """
        log.debug('Running %s analyser', __name__)
        self.name = 'strings'
        self.output.results = self.get_all_strings()