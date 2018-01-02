import os
import logging

import pefile
import yara
from lib.core import Classifier

class FALLCHILL_x86(Classifier):

    classifier_tag = 'FALLCHILL_x86'

    def execute(self):

