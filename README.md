# Yara Framework

The Yara framework allows automated yara generation while at the same time allowing granular analysis on interesting files.

The framework is split between classifiers, analysers and processors. 

## Classifiers

Classifiers are modules that will run against a file and if deemed interesting by the classifier it will tag it. So this can be thought of not only as a file type identification but also for family or APT group (given there are some traits that the classifier can attribute on).

## Analysers

Analysers are modules that will run on classified files. This is set in a configuration file. 
For example:
```
[PE]
Analysers = strings, apis, 
[APT1]
Analysers = strings, apis, c2_function
````

In the above configuration all files classified as PE will have the strings and apis analysers run on them. Similarly, any files taged as APT1 the strings, apis and c2_function analysers will run on them.

## Processors

Finally, after all the analysers for a specific tag are run, say PE, the processors for that tag are invoked. The processors will take the output from the analysers and generate a condition. The processor can either return one condition for all files similarly classified or it can produce multiple conditions. This is up to the processor. What’s is definite is that each processor will run on all files classified. 

The set of conditions produced by each processor are then OR’ed together to form a single Yara rule for the set of files classified as similar. 




## Example 
File1 = PE and APT1

File 2 = JPEG

File3 = PE, SYS and APT1

File4 = PE`

The configuration file looks like this
```
[PE]
Analysers = strings, apis
Processors = strings, apis
[JPEG]
Analysers = strings
Procesors = strings
[APT1]
Analysers = strings, apt1
Processors = strings, apt1
[SYS]
Analysers = strings, sys_analyser
Processors = strings, sys_conditions
```

Given the above configuration a Yara rule will be produced for each classification so there will be 1 yara rule for PE files,  1 for APT1 files, 1 for JPEG files and 1 for SYS files. 

This means that the yara rule for PE files will detect files 1, 3 and 4. The yara rule for APT1 will detect files 1 and 3 while there will the yara rules for JPEG and SYS will detect files 2 and 3 respectively. 
Since each processor will produce a list of conditions, the conditions from all processors for each file class will be OR’ed together to ensure that they all detect as intended and no condition can cause the yara rule to fail detection. 



