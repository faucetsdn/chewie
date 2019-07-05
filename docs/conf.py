# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# http://www.sphinx-doc.org/en/master/config

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys
sys.path.insert(0, os.path.abspath('../'))


# -- Project information -----------------------------------------------------

project = 'Chewie'
copyright = '2019, Chewie Developers'
author = 'Chewie Developers'


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.graphviz'
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'README.rst', 'Thumbs.db', '.DS_Store']

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd_theme'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']


# -- Magic to run sphinx-apidoc automatically -----------------------------

# See https://github.com/rtfd/readthedocs.org/issues/1139
# See https://github.com/faucetsdn/faucet/blob/master/docs/conf.py
# on which this is based.

def run_apidoc(_):
    """Call sphinx-apidoc on chewie module"""
    from sphinx.ext.apidoc import main as apidoc_main
    apidoc_main(['-e', '-o', 'source/apidoc', '../chewie'])


def build_state_machine_diagrams(_):
    from chewie.state_machines.eap_state_machine import FullEAPStateMachine
    from chewie.state_machines.mab_state_machine import MacAuthenticationBypassStateMachine \
        as MABStateMachine
    from datetime import datetime
    now = datetime.now().time()
    FullEAPStateMachine(None, None, None, None, None, None, None, None, True
                        ).get_graph().draw('eap_state_machine.png', prog='dot')

    MABStateMachine(None, None, None,None, None, None, True).get_graph().draw(
        'mab_state_machine.png', prog='dot')


def setup(app):
    """ Add hooks into Sphinx to change behaviour and autogen documentation """

    # Add custom css
    app.add_css_file("css/responsive-tables.css")
    # Override Sphinx setup to trigger sphinx-apidoc.
    app.connect('builder-inited', run_apidoc)
    # Build State Machine Graphs
    app.connect('builder-inited', build_state_machine_diagrams)
