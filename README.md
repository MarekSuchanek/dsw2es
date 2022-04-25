Simple script solution for converting and importing DS Wizard questionnaires into an external Elastic index, in RDA Common maDMP format.

Known problems:
* Different versions of python elasticsearch module can cause errors like: TypeError: index() got an unexpected keyword argument 'document'.  
Using elasticsearch-7.16.3 should work.
* Encoding errors (Linux only?) can be handled by running this script as: 
PYTHONIOENCODING=utf-8 python3 dsw2es.py
