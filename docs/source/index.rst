.. pytls13 documentation master file, created by
   sphinx-quickstart on Mon Apr  3 09:23:54 2023.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to pytls13's documentation!
===================================


``pytls13`` implements a TLS 1.3 client and relies on ``pylurk`` for all cryptographic operations related to the client authentication. 

``pytl13`` can be used as follows:

.. code-block::

   $ cd examples/cli/
   $ ./tls_client --connectivity 'lib_cs' https://www.google.com

``pytls13`` leverages the Limited Use of Remote Keys (LURK) framework as well as it extension for TLS 1.3. `draft-mglt-lurk-lurk <https://datatracker.ietf.org/doc/draft-mglt-lurk-lurk/>`_ `draft-mglt-lurk-tls13 <https://datatracker.ietf.org/doc/draft-mglt-lurk-tls13/>`_.
LURK is a generic protocol whose purpose is to support specific interactions with a given cryptographic material, which is also known as Cryptographic Service (CS). In our case ``pytls13`` implements the TLS Engine (E) while ``pylurk`` implements the CS as depicted below:

.. code-block::

   +----------------------------+
   |       TLS Engine (E)       |
   +------------^---------------+
                | (LURK/TLS 1.3)
   +------------v---------------+
   | Cryptographic Service (CS) |
   | private_keys               |
   +----------------------------+

   TLS being split into a CS and an Engine

`pytls13 documentation <https://pytls13.readthedocs.io/en/latest/>`_ provides **Examples of TLS 1.3 client** and  **Using ``pytls13`` and ``pylurk``\ ** sections with detailed examples on how to combine the TLS engine (E) and the Crypto Service (CS) with.  The **LURK-T TLS 1.3 client** section providing a complete example where the CS runs into a Trusted Execution Enclave (TEE) - SGX in our case. 

Installation
------------

Currently the cli scripts are not installed via pip3 package, so one need to install it manually from the git repo.

The simple installation is as follows:


#. Install ``pytls13`` and ``pylurk`` from the git repo.
   ``git clone https://github.com/mglt/pytls13.git``
   ``git clone https://github.com/mglt/pylurk.git tls13``. Note that for a very limited usage pip3 pylurk maybe sufficient. 
#. Update in ``tls_client``\ , in pytls13.git/example/cli`

   * ``CS_GRAMINE_DIR``\ : the location of the ``pylurk.git/example/cli`` directory
   * ``GRAMINE_DIR`` the directory of the Gramine directory
   * The path of the ``pylurk`` and ``pytls13`` modules indicated by the ``sys.path.insert`` directive.

For a more advamce usage - that is the CS please follow the ``pylurk`` installation steps.

For a more advance us involving to use of TEE please install Gramine.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   mypages/tls13_client_examples
   mypages/lurk-t_tls_client
   mypages/developper_notes
   modules

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
