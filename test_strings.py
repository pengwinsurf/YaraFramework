#!python3

import os
import re
import json
import csv
import re

with open('C:\\NCC-git\\YaraFramework\\log\\strings_extracted.out', 'r') as fh:
    result = json.loads(fh.read())


with open('C:\\NCC-git\\YaraFramework\\conf\\string_scores.csv', newline='') as fh:
    reader = csv.reader(fh, delimiter='\t', quotechar='~')

    test_string = "impersonate"
    for row in reader:
        if re.search(row[0], test_string, re.IGNORECASE):
            print(row[0])
        

    

