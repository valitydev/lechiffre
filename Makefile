REBAR ?= $(shell which rebar3 2>/dev/null || which ./rebar3)
SUBMODULES = build_utils
SUBTARGETS = $(patsubst %,%/.git,$(SUBMODULES))

UTILS_PATH := build_utils
TEMPLATES_PATH := .

# Name of the service
SERVICE_NAME := lechiffre
# Service image default tag
SERVICE_IMAGE_TAG ?= $(shell git rev-parse HEAD)
# The tag for service image to be pushed with
SERVICE_IMAGE_PUSH_TAG ?= $(SERVICE_IMAGE_TAG)

# Base image for the service
BASE_IMAGE_NAME := service-erlang
BASE_IMAGE_TAG := da0ab769f01b650b389d18fc85e7418e727cbe96

BUILD_IMAGE_TAG := 4536c31941b9c27c134e8daf0fd18848809219c9

CALL_ANYWHERE := \
	submodules \
	all compile xref lint dialyze test \
	clean distclean check_format format

CALL_W_CONTAINER := $(CALL_ANYWHERE)

.PHONY: $(CALL_W_CONTAINER) all

all: compile

-include $(UTILS_PATH)/make_lib/utils_container.mk
-include $(UTILS_PATH)/make_lib/utils_image.mk

$(SUBTARGETS): %/.git: %
	git submodule update --init $<
	touch $@

submodules: $(SUBTARGETS)

compile: submodules
	$(REBAR) compile

test:
	$(REBAR) ct

clean:
	$(REBAR) clean

distclean:
	$(REBAR) clean -a

xref:
	$(REBAR) as test xref

dialyze:
	$(REBAR) as test dialyzer

lint:
	elvis rock

check_format:
	$(REBAR) as test fmt -c

format:
	$(REBAR) fmt -w
