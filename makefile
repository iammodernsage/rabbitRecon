# rabbitRecon Makefile
# Build and installation management

PYTHON = python3
PIP = pip3
CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC
LDFLAGS = -shared -lpthread

# Project structure
SRC_DIR = .
CORE_DIR = $(SRC_DIR)/core
FUZZ_DIR = $(SRC_DIR)/fuzz
MODULES_DIR = $(SRC_DIR)/modules
REPORTS_DIR = $(SRC_DIR)/reports
TESTS_DIR = $(SRC_DIR)/tests

# Targets
.PHONY: all install uninstall clean test build

all: build

# Build C core components
build: $(CORE_DIR)/librabbitRecon.so

$(CORE_DIR)/librabbitRecon.so: $(CORE_DIR)/scanner.o $(CORE_DIR)/socket_utils.o
	$(CC) $(LDFLAGS) -o $@ $^

$(CORE_DIR)/scanner.o: $(CORE_DIR)/scanner.c $(CORE_DIR)/scanner.h $(CORE_DIR)/socket_utils.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(CORE_DIR)/socket_utils.o: $(CORE_DIR)/socket_utils.c $(CORE_DIR)/socket_utils.h
	$(CC) $(CFLAGS) -c -o $@ $<

# Installation
install: build
	$(PIP) install -e .
	cp $(CORE_DIR)/librabbitRecon.so /usr/local/lib/
	ldconfig

uninstall:
	$(PIP) uninstall rabbitRecon
	rm -f /usr/local/lib/librabbitRecon.so

# Development
dev:
	$(PIP) install -e .[dev]

test:
	cd $(TESTS_DIR) && $(PYTHON) -m pytest -v

clean:
	rm -f $(CORE_DIR)/*.o $(CORE_DIR)/*.so
	rm -rf *.egg-info build dist
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -delete

# Documentation
docs:
	cd docs && make html

# Docker
docker-build:
	docker build -t rabbitRecon .

docker-run:
	docker run -it rabbitRecon

# Formatting
format:
	black $(SRC_DIR)
	isort $(SRC_DIR)

# Linting
lint:
	flake8 $(SRC_DIR)
	mypy $(SRC_DIR)


# Build the shared library for Python integration
librabbitRecon.so: core/scanner.o core/socket_utils.o
	$(CC) -shared -o $@ $^ -lpthread

core/scanner.o: core/scanner.c core/scanner.h core/socket_utils.h
	$(CC) -c -fPIC -o $@ $<

core/socket_utils.o: core/socket_utils.c core/socket_utils.h
	$(CC) -c -fPIC -o $@ $<
