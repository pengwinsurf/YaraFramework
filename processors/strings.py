import logging
import os
import csv
import re

from lib.core import Processor, ROOT_DIR
from lib.yara import YaraRule

log = logging.getLogger(__name__)

SCORING_FILE = os.path.join(ROOT_DIR, 'conf', 'string_scores.csv')

class Strings(Processor):

    
    def add_strings(self, yara_strings, ordered_list, string_modifiers=None):

        for count in range(len(ordered_list)):
            current_string = str(ordered_list[count][1])
            log.debug('Adding unicode string: %s', current_string)
            # Only add the top 5 strings
            if count > 5:
                return
            yara_strings.append(self.current_rule.create_text(current_string, modifiers=string_modifiers))

    def string_score(self, string_list):
        """ Assign scores to a list of strings
        """
        scored_strings = {}
        try:
            with open(SCORING_FILE, newline='') as fh:
                reader = csv.reader(fh, delimiter='\t', quotechar='~')
                for string in string_list:
                    fh.seek(0)
                    scored_strings.setdefault(string, 0)
                    for row in reader:
                        regex_string = row[0]
                        score = int(row[1])
                        if re.search(regex_string, string, re.IGNORECASE):
                            log.debug('String %s scored %s', string, score)
                            scored_strings[string] += score                
        except IOError:
            log.error('Could not open string scores file')
            return None
        
        return scored_strings



    def count_file_occurence(self, result_data, string_list, filename):
        """ Given a list of strings determi
        """
        for string in string_list:
            file_list = result_data.setdefault(string, [])
            if filename not in file_list:
                file_list.append(filename)           


    def get_intersection_set(self, string_set):
        """ Given a dictionary of strings return a list of
            all strings that occur in all files
        
        Args:
            string_set: A dict of string: [list of files it occured in] 
        
        Returns:
            list of overlapped strings
        """
        overlapped_strings = []
        for string in string_set:
            if len(string_set[string]) < len(self.strings_data):
                continue
            
            overlapped_strings.append(string)
        
        return overlapped_strings

    def run(self):
        self.ascii_strings = {}
        self.unicode_strings = {}

        try:
            ## We are only interested in the strings analyser
            ## output in this processing module

            self.strings_data = self.analysis['strings']

        except KeyError as e:
            log.debug('No strings data found in analyser')
            return None

        log.debug('Counting the occurence of strings from all string results')
        log.debug('The number of files analysed is: %s', len(self.strings_data))

        ## There must be a more optimal way of doing this
        ## this alg with have a stupid O()

        ascii_dict = {}
        unicode_dict = {}
        for file_result in self.strings_data:
            self.count_file_occurence(ascii_dict, file_result.results['ascii'], file_result.filename)
            self.count_file_occurence(unicode_dict, file_result.results['unicode'], file_result.filename)
        
        ## Only for demo purposes we will take the highest hitting strings
        ## Of course this could be a bad FP string. 
        ascii_overlap_strings = self.get_intersection_set(ascii_dict)
        unicode_overlap_strings = self.get_intersection_set(unicode_dict)

        log.debug('Created overlap dicts for unicode and ascii strings. \
                    Ascii set size: %d - Unicode set size: %d', len(ascii_overlap_strings), \
                    len(unicode_overlap_strings))

        scored_ascii_string = self.string_score(ascii_overlap_strings)
        scored_unicode_string = self.string_score(unicode_overlap_strings)

        sorted_ascii_strings = sorted(zip(scored_ascii_string.values(), scored_ascii_string.keys()), reverse=True)
        sorted_unicode_strings = sorted(zip(scored_unicode_string.values(), scored_unicode_string.keys()), reverse=True)

        strings = []
        self.current_rule = YaraRule()

        self.add_strings(strings, sorted_ascii_strings)
        self.add_strings(strings, sorted_unicode_strings, string_modifiers=['fullword', 'wide'])

        return self.current_rule.and_condition(strings)

