# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'pytls13'
copyright = '2023, Daniel Migault'
author = 'Daniel Migault'
release = '0.1'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

## path to python modules
## We include these paths to ensure the doc is generated from the current code
## we coudl have gon ethrough the requirements.txt and pytls13
import os
import sys
## sys.path.insert( 0, os.path.abspath( '../../../pylurk.git/src/pylurk/' ))
## relative path for RTD
### LOCAL CONFIGURATION
sys.path.insert( 0, os.path.abspath( '../../../src' ))
sys.path.insert( 0, os.path.abspath( '../../../src/pytls13' ))
## when locally generated via make html
## providing the pytls13 directory enables autodoc to find the modules. 
## it seems that pytls13.module is not consider properly
## maybe that could be also resolved by adding __init__ in our package.
### RTD CONFIGURATION
sys.path.insert( 0, os.path.abspath( '../../src' ))
sys.path.insert( 0, os.path.abspath( '../../src/pytls13' ))

### TO BE REMOVED
#sys.path.insert( 0, os.path.abspath( '/home/mglt/gitlab/pytls13/src/pytls13' ))
#sys.path.insert( 0, os.path.abspath( '/home/mglt/gitlab/pytls13/src' ))
#sys.path.insert( 0, os.path.abspath( '/home/mglt/gitlab/pylurk.git/src' ))


## autodoc and napoleon (Google Python style)
extensions = [ 'sphinx.ext.autodoc', 'sphinx.ext.napoleon' ]
## this extension is expected to understand .md files
# , "myst_parser" ]

templates_path = ['_templates']
exclude_patterns = []

## we include the Napoleon settings. Current values 
## are the default except for including the __init__ as we
## used toi describe th efunction in the init as opposed to
## the class or function itslef.
# Napoleon settings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = False
napoleon_use_admonition_for_notes = False
napoleon_use_admonition_for_references = False
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_preprocess_types = False
napoleon_type_aliases = None
napoleon_attr_annotations = True


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'alabaster'
html_static_path = ['_static']

