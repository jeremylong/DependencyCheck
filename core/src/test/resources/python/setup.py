from setuptools import setup

about = {}
execfile('eggtest/__about__.py', about)
setup(name = about['__title__'],
      packages = ['eggtest'],
      version = about['__version__'],
      description = about['__summary__'],
      url = about['__uri__'],
      author = about['__author__'],
      author_email = about['__email__'])