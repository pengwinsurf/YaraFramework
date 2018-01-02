import os
import logging
import configparser
import pkgutil
import inspect
import importlib
import threading
import queue

import analysers
import classifiers
import processors

from concurrent.futures import ThreadPoolExecutor
from time import sleep

from lib.yara import YaraRule, YaraCondition, YaraBuilder, OrCondition

log = logging.getLogger(__name__)

ROOT_DIR = os.path.abspath(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..'))

class Config(object):

    def __init__(self, cfg_file):
        self._config = configparser.ConfigParser()
        self._config.read(cfg_file)
        self._data = {}
        for section in self._config.sections():
            section_data = {}
            for name, val in self._config.items(section):
                try:
                    value = self._config.getboolean(section, name)
                except ValueError:
                    try:
                        value = self._config.getint(section,name) 
                    except ValueError:
                        value = self._config.get(section, name)
                
                section_data[name] = value
            self._data[section] = section_data
    
    @property
    def data(self):
        return self._data
           
class AnalyserOutput():

    def __init__(self):

        self.filename = ''
        self.results = {}

class Processor():
    """ This is an abstract class for processors
    """

    def __init__(self, analyser_results):
        self.analysis = analyser_results
        self.condition = None
    
    def run(self):
        NotImplemented
    
    # TODO
    def _by_files(self):
        """ Organises analysis results by file rather than by analysis module. 

        Returns:
            A dict of {files, analysis_results}
        """
        pass
        

class Analyser():
    """ Abstract class for analysers.
        Each analyser runs on one file at a time
    """

    def __init__(self, data):
        """ Init the analysers
        """
        self._data = data
        self.name = ''
        # The output object 
        # 
        self.output = AnalyserOutput()
    
    @property
    def data(self):
        return self._data

    def run(self):
        raise NotImplementedError
    
    def stop(self):
        raise NotImplementedError

class Classifier(object):

    def __init__(self, data):
        self.classification = []
        self._data = data
    
    @property
    def data(self):
        return self._data

    def execute(self):
        raise NotImplementedError

class Scheduler():
    """ Responsible for core instrumentation of Yara rule
        generation.
    """

    def __init__(self):
        """ Init the scheduler class
        """
        self.c_lock = threading.Lock()
        self.a_lock = threading.Lock()
        self._classifiers = []
        self._analysers = []
        self._processors = []
        self._tasks = []
        self.classified = {}
        config_file = os.path.join(ROOT_DIR, 'conf', 'main.conf')
        self._conf = Config(config_file)
        self._init_modules()


    def _init_modules(self):
        self._import_mods(classifiers)
        self._import_mods(analysers)
        self._import_mods(processors)


    def _import_mods(self, package):
        """ Import the modules in each directory

        Args:
            Thats a package directory
        """
        prefix = package.__name__+'.'
        log.debug('importing modules in: %s', package.__name__)
        prefix = package.__name__ + '.'
        for _, module_name, ispkg in pkgutil.iter_modules(package.__path__, prefix):
            if ispkg:
                continue
            log.debug('Importing module: %s', module_name)
            module = importlib.import_module(module_name)
            for _, m_class in inspect.getmembers(module, inspect.isclass):
                if issubclass(m_class, Classifier) and m_class is not Classifier:
                    if m_class.classifier_tag in self._conf.data:
                        tag = m_class.classifier_tag
                        if self._conf.data[tag]['enabled']:
                            self._classifiers.append(m_class)

                if issubclass(m_class, Analyser) and m_class is not Analyser:
                    self._analysers.append(m_class)
                
                if issubclass(m_class, Processor) and m_class is not Processor:
                    self._processors.append(m_class)


    def add_task(self, file_path):
        """ Add a task to the list of tasks to process

        Args:
            file_path = string carrying the full file path of the file.
        """
        self._tasks.append(file_path)


    def _run_classifier(self, classifier):
        """ Given a classifier instance run the classifier on all tasks.
            Each classifier if it correctly identifies the file 
            will update the tag with the list of files it classified. 
        
        Args:
            classifier: A classifier class.
        """

        for task in self._tasks:
            with open(task, 'rb') as file_handle:
                data = file_handle.read()
            try:
                current_classifier = classifier(data)
            except:
                log.exception('Failed to load the classifier module: %s', classifier)
            
            if current_classifier.execute():
                tag = current_classifier.classifier_tag
                with self.c_lock:
                    task_list = self.classified.setdefault(tag, [])
                    task_list.append(task)
                    log.debug('File %s classified as %s', task, tag)

        return True
                

    def _run_analyser(self, analyser, files):
        """"
        """
        analyser_output = []
        for file_path in files:
            with open(file_path, 'rb') as file_handle:
                data = file_handle.read()
                log.debug('Starting analyser %s on %s', analyser.__name__, file_path)
                current_analyser = analyser(data)
            current_analyser.run()
            current_analyser.output.filename = file_path
            analyser_output.append(current_analyser.output)

        return current_analyser.name,  analyser_output
    
    def _run_processor(self, processor, all_results):
        """ For each processor the dict of all_results is passed to 
            an instance of that processor. Each processor instance will
            populate a condition.

            Each processor should return a condition that gets included in
            the yara signature.

        Args:
            processor: The processor class to instantiate
            all_results: A dict of {analyser_tag: [analyser_outputs]}
        
        Returns:
            A condition produced by the processor
        """
        log.debug('Starting processor %s', processor.__name__)
        current_processor = processor(all_results)
        result = current_processor.run()
        if not result:
            log.error('Processor %s return no output.', processor.__name__)

        return result

    
    def process(self):

        # First we run a thread for each classifier
        # All enabled classifiers will run on all files
        c_threads = []
        c_pool = ThreadPoolExecutor(len(self._classifiers))
        for classifier in self._classifiers:
            worker = c_pool.submit(self._run_classifier, (classifier))
            c_threads.append(worker)

        for thread in c_threads:
            while not thread.done():
                sleep(1)

        log.debug('Finished executing classifiers')
        # Once all classification threads finish
        # we loop over all the classifier tags
        # its important to note that there is a 
        # many to many relationship between classifiers
        # and files. A file can be classified by multiple
        # classifiers and a classifier will obviously classify 
        # multiple files. 
        all_analyser_results = {}
        a_pool = ThreadPoolExecutor(len(self._analysers))
        p_pool = ThreadPoolExecutor(len(self._processors))

        analyser_names = [analyser_class.__name__.lower() for analyser_class in self._analysers]
        processor_names = [processor_class.__name__.lower() for processor_class in self._processors]

        for tag in self.classified:
            a_threads = []
            p_threads = []
            proc_results = []

            log.debug('Starting analysers ...')
            for analyzer_class in self._analysers:
                if analyzer_class.__name__.lower() in [x.lower() for x in self._conf.data[tag]['analysers'].split(',')]:
                    future_thread = a_pool.submit(self._run_analyser, analyzer_class, self.classified[tag])
                    a_threads.append(future_thread)
            
            for thread in a_threads:
                while not thread.done():
                    sleep(1)
                    
                # If no output from analyser then continue     
                if not thread.result():
                    continue

                analyser_name, analyser_output = thread.result()
                out_list = all_analyser_results.setdefault(analyser_name, [])
                out_list.extend(analyser_output)                    

            log.debug('Finished running analysers')
            ## Now we have run all the analysers for that classifier
            ## We will now run the processors for that tag and output a yara rule
            ## for that tag

            log.debug('Starting processors ...')
            for processor_class in self._processors:
                if processor_class.__name__.lower() in [x.lower() for x in self._conf.data[tag]['processors'].split(',')]:
                    p_worker = p_pool.submit(self._run_processor, processor_class, all_analyser_results)
                    p_threads.append(p_worker)
            
            for thread in p_threads:
                while not thread.done():
                    sleep(1)

                # If no result from processor continue    
                if not thread.result():
                    continue

                proc_results.append(thread.result())

            ## All processor threads completed succesfully
            ## for this tag. Now we need to generate a yara rule
            ## for this tag given the output from all the processors. 

            self.generate_yara(tag, proc_results)

    def generate_yara(self, tag, conditions):
        """ Given a list of conditions this function
            will generate a yara rule by OR'ing the conditions
        """
        
        filename = '{}.yar'.format(tag)

        current_rule = YaraRule()
        yara_writer = YaraBuilder()
        num_conditions = len(conditions)
        log.debug('%s conditions for %s', num_conditions, tag)
        if num_conditions > 1:
            final_cond = current_rule.or_condition(conditions)
        else:
            final_cond = conditions[0]

        log.debug('Evaluating yara rule')
        condition_string = yara_writer.eval_cond(final_cond)
        all_strings = yara_writer.strings

        log.debug('Generating yara rule')
        yara_rule = "rule\t%s\t{\n" % tag
        yara_rule += "\tstrings:\n"
        rule_strings = ""
        for key, value in all_strings.items():
            rule_strings += '\t\t{0} = {1}\n'.format(key, value)

        yara_rule += rule_strings

        yara_rule += "\tcondition:\n\t\t{}".format(condition_string)
        yara_rule += '\n}'

        with open(filename, 'w') as fh:
            fh.write(yara_rule)






    
    
             


            
        





                        
                

                            
                            


                        




               

    
