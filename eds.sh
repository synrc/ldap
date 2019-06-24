#!/bin/sh

erl \
    -name eds@localhost \
    -config sys.config \
    -pa ../emongo/ebin \
    -pa ebin \
    -boot start_sasl \
    -eval "application:start(eds)"
