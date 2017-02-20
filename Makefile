VIRTUALENV = virtualenv
VENV := $(shell echo $${VIRTUAL_ENV-.venv})
PYTHON = $(VENV)/bin/python
TOX = $(VENV)/bin/tox
TEMPDIR := $(shell mktemp -d)
DEV_STAMP = $(VENV)/.dev_env_installed.stamp
INSTALL_STAMP = $(VENV)/.install.stamp

help:
	@echo "Please use 'make <target>' where <target> is one of"
	@echo "  install                     install dependencies and prepare environment"
	@echo "  install-dev                 install dependencies and everything needed to run tests"
	@echo "  build-requirements          install all requirements and freeze them in requirements.txt"
	@echo "  tests-once                  only run the tests once with the default python interpreter"
	@echo "  flake8                      run the flake8 linter"
	@echo "  tests                       run all the tests with all the supported python interpreters (same as travis)"
	@echo "  clean                       remove *.pyc files and __pycache__ directory"
	@echo "  distclean                   remove *.egg-info files and *.egg, build and dist directories"
	@echo "  maintainer-clean            remove the .tox and the .venv directories"
	@echo "Check the Makefile to know exactly what each target is doing."


install: $(INSTALL_STAMP)
$(INSTALL_STAMP): $(PYTHON) setup.py
	$(VENV)/bin/pip install -U pip
	$(VENV)/bin/pip install -Ue .
	touch $(INSTALL_STAMP)

install-dev: $(INSTALL_STAMP) $(DEV_STAMP)
$(DEV_STAMP): $(PYTHON) dev-requirements.txt
	$(VENV)/bin/pip install -Ur dev-requirements.txt
	touch $(DEV_STAMP)

virtualenv: $(PYTHON)
$(PYTHON):
	virtualenv $(VENV)

build-requirements:
	$(VIRTUALENV) $(TEMPDIR)
	$(TEMPDIR)/bin/pip install -U pip
	$(TEMPDIR)/bin/pip install -Ue .
	$(TEMPDIR)/bin/pip freeze | grep -v -- '-e' > requirements.txt

tox: $(TOX)
$(TOX): virtualenv
	$(VENV)/bin/pip install tox

tests: tox
	$(VENV)/bin/tox

tests-once: install-dev
	$(VENV)/bin/py.test --cov-report term-missing --cov-fail-under 100 --cov portier

flake8: install-dev
	$(VENV)/bin/flake8 portier tests

clean:
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -type d | xargs rm -fr
	rm -fr docs/_build/

distclean: clean
	rm -fr *.egg *.egg-info/ dist/ build/

maintainer-clean: distclean
	rm -fr .venv/ .tox/
