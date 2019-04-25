REPORTER = spec
BASE = .
JSHINT = ./node_modules/.bin/jshint

all: lint test

test:
	@NODE_ENV=test ./node_modules/.bin/mocha \
		--reporter $(REPORTER) \
		--timeout 10000

lint:
	$(JSHINT) index.js --config $(BASE)/.jshintrc && \
	$(JSHINT) ./lib --config $(BASE)/.jshintrc && \
	$(JSHINT) ./test --config $(BASE)/.jshintrc

.PHONY: test docs