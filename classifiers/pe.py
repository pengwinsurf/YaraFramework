import os
import logging

from lib.core import Classifier


log = logging.getLogger(__name__)

class PE(Classifier):
    
    classifier_tag = 'PE'

    def execute(self):
        """ Check if the file is a PEfile
        """
        mz = b'MZ'
        if mz == self.data[:2]:
            image_nt_hdr_off = int.from_bytes(self.data[0x3c:0x3f], byteorder='little')
            if b'PE\x00\x00' == self.data[image_nt_hdr_off:image_nt_hdr_off+4]:
                return True

