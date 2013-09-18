"""
<Program Name>
  statement_coverage.py

<Author>
  Konstantin Andrianov

<Started>
  March 20, 2013.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Measure test coverage.

NOTE: This script is based on third party software.  In order to use this
script install Ned Batchelder's coverage.py: 
http://nedbatchelder.com/code/coverage/


"""

import os
import sys

# Try to import coverage.py.  Coverage.py is a third party software.
try:
  coverage = __import__('coverage')
except ImportError, error:
  error_msg = ("\nIt appears that coverage.py is not installed.  Install "+
               "Ned Batchelder's coverage.py "+
               "('http://nedbatchelder.com/code/coverage/') and try again.\n")
  print error_msg
  raise


cov = coverage.coverage()
cov.start()

try:
  current_directory = os.getcwd()
  current_directory_content = os.listdir(current_directory)

  # Find test scripts and import them.
  test_modules = []  # Test modules.
  tested_modules = []  # Modules that are tested by the 'test_modules'.

  for _file in current_directory_content:
    if _file.startswith('test') and _file.endswith('.py'):

      _file = os.path.splitext(_file)[0]
      test_modules.append(_file)

      # Import the module.
      try:
        module = __import__(_file)
      except ImportError, error:
        print 'Unable to load the module: '+_file
        raise

      _file = '.'+_file[5:]
      tested_modules.append(_file)

finally:
  cov.stop()


# Include quickstart.
tested_modules.remove('.quickstart')
tested_modules.append('quickstart')

# Extracting tuf modules.
tuf_modules = {}  # list of all loaded tuf modules.
for module_name in sys.modules:
  if module_name.startswith('tuf') or module_name.startswith('quickstart'):
    tuf_modules[module_name] = sys.modules[module_name]

# Tested module paths.
tested_module_paths = []
for module_name in tuf_modules:
  for tested_module in tested_modules:
    if module_name.endswith(tested_module):
      tested_module_paths.append(tuf_modules[module_name].__file__)

cov.report(tested_module_paths)