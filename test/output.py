"""
Variety of filters for the python unit testing output, which can be chained
together for improved readability.
"""

import re
import logging

import stem.util.enum
import stem.util.term as term

LineType = stem.util.enum.Enum("OK", "FAIL", "ERROR", "SKIPPED", "CONTENT")

LINE_ENDINGS = {
  " ... ok": LineType.OK,
  " ... FAIL": LineType.FAIL,
  " ... ERROR": LineType.ERROR,
  " ... skipped": LineType.SKIPPED,
}

LINE_ATTR = {
  LineType.OK: (term.Color.GREEN,),
  LineType.FAIL: (term.Color.RED, term.Attr.BOLD),
  LineType.ERROR: (term.Color.RED, term.Attr.BOLD),
  LineType.SKIPPED: (term.Color.BLUE,),
  LineType.CONTENT: (term.Color.CYAN,),
}

def apply_filters(testing_output, *filters):
  """
  Gets the tests results, possably processed through a series of filters. The
  filters are applied in order, each getting the output of the previous.
  
  A filter's input arguments should be the line's (type, content) and the
  output is either a string with the new content or None if the line should be
  omitted.
  
  Arguments:
    testing_output (str) - output from the unit testing
    filters (list) - functors to be applied to each line of the results
  
  Returns:
    str with the processed test results
  """
  
  results = []
  
  for line in testing_output.split("\n"):
    # determine the type of the line
    line_type = LineType.CONTENT
    
    for ending in LINE_ENDINGS:
      if ending in line:
        line_type = LINE_ENDINGS[ending]
        break
    
    for result_filter in filters:
      line = result_filter(line_type, line)
      if line == None: break
    
    if line != None:
      results.append(line)
  
  return "\n".join(results)

def colorize(line_type, line_content):
  """
  Applies escape sequences so each line is colored according to its type.
  """
  
  return term.format(line_content, *LINE_ATTR[line_type])

def strip_module(line_type, line_content):
  """
  Removes the module name from testing output. This information tends to be
  repetative, and redundant with the headers.
  """
  
  m = re.match(".*( \(.*?\)).*", line_content)
  if m: line_content = line_content.replace(m.groups()[0], "", 1)
  return line_content

def align_results(line_type, line_content):
  """
  Strips the normal test results, and adds a right aligned variant instead with
  a bold attribute.
  """
  
  if line_type == LineType.CONTENT: return line_content
  
  # strip our current ending
  for ending in LINE_ENDINGS:
    if LINE_ENDINGS[ending] == line_type:
      line_content = line_content.replace(ending, "", 1)
      break
  
  # skipped tests have extra single quotes around the reason
  if line_type == LineType.SKIPPED:
    line_content = line_content.replace("'(", "(", 1).replace(")'", ")", 1)
  
  if line_type == LineType.OK:
    new_ending = "SUCCESS"
  elif line_type in (LineType.FAIL, LineType.ERROR):
    new_ending = "FAILURE"
  elif line_type == LineType.SKIPPED:
    new_ending = "SKIPPED"
  else:
    assert False, "Unexpected line type: %s" % line_type
    return line_content
  
  return "%-61s[%s]" % (line_content, term.format(new_ending, term.Attr.BOLD))

class ErrorTracker:
  """
  Stores any failure or error results we've encountered.
  """
  
  def __init__(self):
    self._errors = []
  
  def has_error_occured(self):
    return bool(self._errors)
  
  def get_filter(self):
    def _error_tracker(line_type, line_content):
      if line_type in (LineType.FAIL, LineType.ERROR):
        self._errors.append(line_content)
      
      return line_content
    
    return _error_tracker
  
  def __iter__(self):
    for error_line in self._errors:
      yield error_line

class LogBuffer(logging.Handler):
  """
  Basic log handler that listens for all stem events and stores them so they
  can be read later. Log entries are cleared as they are read.
  """
  
  def __init__(self, runlevel):
    logging.Handler.__init__(self, level = runlevel)
    self.formatter = logging.Formatter(
      fmt = '%(asctime)s [%(levelname)s] %(message)s',
      datefmt = '%D %H:%M:%S')
    
    self._buffer = []
  
  def is_empty(self):
    return not bool(self._buffer)
  
  def __iter__(self):
    while self._buffer:
      yield self.formatter.format(self._buffer.pop(0))
  
  def emit(self, record):
    self._buffer.append(record)
