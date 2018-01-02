import os
import logging

log = logging.getLogger(__name__)


# class FileInfo():
#     """ Holds information about each file
#     """

#     def __init__(self, file_path):
#         full_path = os.path.abspath(file_path)
#         if os.path.exists(full_path):
#             self._path = full_path
#         else:
#             log.error('File does not exist %s', full_path)
#             raise IOError('File does not exist.')

#         self.file_size = self._calc_size()
    
#     @property
#     def file_path(self):
#         return self._path

#     @property
#     def file_size(self):
#         return self._file_size

#     @file_size.setter
#     def file_size(self, value):
#         self._file_size = value
        
#     def _calc_size(self):
#         """ Set's the size of the file in bytes
#         """
#         return os.stat(self._path).st_size

class YaraString(object):
    """ This is a parent class
        that defines the types of strings in a Yara Rule
        for example Hexadecimal strings, text strings, regex
    """

    def __init__(self, value_name=None, value_string=None):
        self._parent = None
        self._start = ''
        self._end = ''
        self._name = '$' + value_name
        if value_string:
            self._string = value_string
        else:
            self._string = ''

    @property
    def string(self):
        """ string property of YaraString
        """
        return self._string

    @string.setter
    def string(self, value_string):
        self._string = value_string
    
    @property
    def name(self):
        """ name property of YaraString
        """
        return self._name

    def eval_string(self):
        """ Returns the match string to be inserted in a Yara rule
        """
        return self._start + self._string + self._end

class HexString(YaraString):
    """ Child class of YaraString for byte expression
        strings in Yara.
    """
    def __init__(self, hex_name, hex_string):
        super().__init__(hex_name, hex_string)
        self._start = '{'
        self._end = '}' 

class TextString(YaraString):
    """ Child class of YaraString for text expression
        strings in Yara.
    """
    def __init__(self, text_name, text_string, modifiers=None):
        super().__init__(text_name, text_string)
        self._start = '"'
        self._end = '"'
        self.modifiers = modifiers

    def eval_string(self):
        log.debug('Evaluating text string')
        text_string = super().eval_string()
        if self.modifiers:
            return ' '.join([text_string, ' '.join(self.modifiers)])
        else:
            return text_string



class RegexString(YaraString):
    """ Child class of YaraString for regular expression
        strings in Yara.
    """

    def __init__(self, regex_name, regex_string):
        super().__init__(regex_name, regex_string)
        self._start = '/'
        self._end = '/'

class YaraCondition(object):
    """ A YaraCondition is node with multiple children of YaraConditions
        and/or YaraStrings
    """

    def __init__(self):
        self._type = ''
        self._children = []
        self._parent = None
    
    def _validate_type(self, value):
        """ Check if a value is of type YaraString or
            YaraCondition
        
        Raises:
            TypeError if value is not YaraCondition or YaraString
        """    

        if isinstance(value, YaraCondition) or isinstance(value, YaraString):
            return True
        else:
            raise TypeError('Invalid expression type')

    def add_expression(self, expression):
        """ Given an expression set the children of the YaraCondition.

        Args:
            expression: YaraCondition or YaraString instance.
        
        Returns:
            True/False depending on sucess to add expression. 
        """
        
        try:
            self._validate_type(expression)
            expression._parent = self
            self._children.append(expression)
        except TypeError:
            log.error('Invalid expression type supplied: %s', type(expression))
            return False
        return True

    def get_children(self):
        """ Returns all expressions of a YaraCondition
        """
        return self._children

class OrCondition(YaraCondition):
    """ Child class of YaraCondition for
        OR conditions
    """
    def __init__(self):
        super().__init__()
        self._type = 'OR'

class AndCondition(YaraCondition):
    """ Child class of YaraCondition for
        AND conditions
    """

    def __init__(self):
        super().__init__()
        self._type = 'AND'

class DataCondition(YaraCondition):
    """ Child class of YaraCondition
        for data check ex. unint(0) == 0x..
    """

    def __init__(self, int_type=None):
        """ If no type is specified the default is unit32
        """
        if not int_type:
            self.int_type = 'uint32'

        if int_type not in ['uint8', 'uint16', 'uint32', 'int8', 'int16', 'int32']:
            raise TypeError('Invalid type supplied')
        
        super().__init__()
        self._type = 'Data'

    def add_expression(self, expression):
        """ 
        Args:
            Expression: A dict of offset-value pair. {offset: value}
        
        Returns
            True/False depending on success
        """

        if not isinstance(expression, dict):
            log.error('Failed to create Data condition')
            return False

        self.offset, self.value = (expression[0], expression[1])

        return True




## Taken from Python Cook Book
class NodeVisitor:
    """ This is a helper class to walk a YaraConditions tree
    """
    def eval_cond(self, node):
        """ This is a dynamic visitor method to walk the tree of YaraConditions
        """
        methname = 'eval_cond_' + type(node).__name__
        meth = getattr(self, methname, None)
        if meth is None:
            meth = self.generic_visit
        return meth(node)
    
    def generic_visit(self, node):
        """ Fail method for unrecognised object types
        """
        raise RuntimeError('No {0} method'.format('visit_' + \
                            type(node).__name__))

class YaraBuilder(NodeVisitor):
    """ Class to walk a YaraConditions tree and interpret the 
        conditions and strings in a Yara signature.
        Attributes:
            strings: A dictionary of name, value pair for strings. 
                For example {$s0: 'badtext'}
    """

    def __init__(self):
        self.strings = {}

    def eval_cond_AndCondition(self,node):
        """ Interpret an AND condition with all it's expressions

        Args:
            node: An AndCondition instance 
        
        Returns:
            condition: a string of the and condition
        """
        condition = '('
        children = node.get_children()
        condition += self.eval_cond(children[0])        
        for child in children[1:]:
            condition = ' and '.join([condition, self.eval_cond(child)])

        condition += ' )'
        return condition

    
    def eval_cond_OrCondition(self, node):
        """ Interpret an OR condition with all it's expressions

        Args:
            node: An OrCondition instance 
        
        Returns:
            condition: a string of the or condition
        """ 
        condition = '( '
        children = node.get_children()
        condition += self.eval_cond(children[0])
        for child in children[1:]:
            condition = ' or '.join([condition, self.eval_cond(child)])
        condition += ' )'

        return condition
    
    def eval_cond_DataCondition(self, node):
        """ Interpret a DataCondition with all it's expressions

        Args:
            node: A DataCondition instance 
        
        Returns:
            condition: a string of the DataCondition
        """
        return '( {0}({1}) == {2} )'.format(node.int_type, node.offset,\
                                            node.value)

    
    def eval_cond_HexString(self, node):
        """ Interpret a HexString node

        Args:
            node: A HexString instance
        
        Returns:
            name: a string of the string name i.e $s0, $s1 ..
        """         
        if node.name not in self.strings.keys():
            self.strings[node.name] = node.eval_string()
        return node.name
        
    
    def eval_cond_TextString(self, node):
        """ Interpret a TextString node

        Args:
            node: A TextString instance
        
        Returns:
            name: a string of the string name i.e $s0, $s1 ..
        """                 
        if node.name not in self.strings.keys():
            log.debug(node.eval_string())
            self.strings[node.name] = node.eval_string()
        return node.name

    def eval_cond_RegexString(self, node):
        """ Interpret a RegexString node

        Args:
            node: A RegexString instance
        
        Returns:
            name: a string of the string name i.e $s0, $s1 ..
        """                 
        if node.name not in self.strings.keys():
            self.strings[node.name] = node.eval_string()
        return node.name

class YaraRule:
    """ Class used to create yara strings and conditions
    """

    def __init__(self):
        """ _indx is an internal count tracker for generated
            string variables. It is incremented every time a string is added. 
            $s0, $s1, $s3 ...
        """
        self._indx = 0

    def create_text(self, input_string, modifiers=None):
        """ Adds a text string to the set of strings to
            match on.

        Args:
            input_string: string value to be matched on.
            modifiers: A string list that includes any modifiers 
                       associated with the string. 
                       For example: 
                       ['nocase', 'fullword', 'wide']
        Returns:
            TextString instance.

        Raises:
            TypeError: if input_string is not an instance of str
            TypeError: if modifiers is not an instance of list       
        """
        if not isinstance(input_string, str):
            raise TypeError('Invalid type expecting str instead', type(input_string))
        if modifiers:
            if not isinstance(modifiers, list):
                raise TypeError('Invalid type expecting list instead', type(modifiers))

        string_name = 's{}'.format(self._indx)
        self._indx += 1

        return TextString(string_name, input_string, modifiers)

    def create_hex(self, input_hex):
        """ Adds a hex string to the set of strings to
            match on.

        Args:
            input_hex: string value that includes the hex bytes 
            to be matched on.

        Returns:
            HexString instance.

        Raises:
            TypeError: if input_hex is not an instance of str                
        """

        if not isinstance(input_hex, str):
            raise TypeError('Invalid input_hex type.') 

        string_name = 's{}'.format(self._indx)
        self._indx += 1
        return HexString(string_name, input_hex)
    
    def create_regex(self, input_regex):
        """ Adds a regular expression string to the set of strings to
            match on.

        Args:
            input_regex: string value that includes the regular expression 
            to be matched on.

        Returns:
            RegexString instance.

        Raises:
            TypeError: if input_regex is not an instance of str                
        """        
        if not isinstance(input_regex, str):
            raise TypeError('Invalid input_hex type.') 

        string_name = 's{}'.format(self._indx)
        self._indx += 1
        return RegexString(string_name, input_regex)
    
    def and_condition(self, expressions):
        """ Creates an and condition given a list of expressions.

        Args:
            expressions: A list of YaraCondition and/or YaraStrings.
        
        Returns:
            If succesful AndCondition instance otherwise None
        """
        if not isinstance(expressions, list) or len(expressions) < 2:
            log.error('Invalid expressions argument. Needs list of at least two instances')
            return None

        and_cond = AndCondition()
        for exp in expressions:
            try:

                and_cond.add_expression(exp)
            
            except TypeError:
                log.error('Failed to create condition. Invalid expression type provided.')
                return None
        
        return and_cond
    
    def or_condition(self, expressions):
        """ Creates an or condition given a list of expressions.

        Args:
            expressions: A list of YaraCondition and/or YaraStrings.
        
        Returns:
            If succesful OrCondition instance otherwise None
        """
        if not isinstance(expressions, list) or len(expressions) < 2:
            log.error('Invalid expressions argument. Needs list of at least two instances')
            return None

        or_cond = OrCondition()
        for exp in expressions:
            try:
                
                or_cond.add_expression(exp)
            
            except TypeError:
                log.error('Failed to create condition. Invalid expression type provided.')
                return None
        
        return or_cond

    def data_condition(self, offset, value, int_type=None):
        """ Creates a data condition.

        Args:
            offset: an int value specifiying the offset in the file

            value: Byte value to be checked at the offset
        
        Returns:
            If succesful DataCondition instance otherwise None
        """

        data_cond = DataCondition(int_type)         
        if not data_cond.add_expression(hex(offset), str(value)):
            return None
        return data_cond
        




# TODO: add more condition child classes 

# class CountCondition(YaraCondition):

#     def __init__(self):
#         self._name = 'count'
    
#     def add_expression(self, conditions):
#         # number of 'badstring' <operator> integer
#         self.evaluator['value'] = conditions['operator']
#         self.evaluator['number'] = conditions['number']
#         self.matches
        


# class OffsetCondition(YaraCondition):
#     def __init__(self):
#         # Type can be 'in'
#         # or 'at'. 
#         # for each there is a different kind of match

#         self._name = 'offset'

# class OffsetConditionIn(OffsetCondition):
#     pass

# class OffsetConditionAt(OffsetCondition):
#     pass

# class FileSizeCondition(YaraCondition):
#     pass

# class OfCondition(YaraCondition):
#     def __init__(self):
#         self._name = 'of'






