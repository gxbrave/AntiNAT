#!/bin/sh
set -eu
# PID 1 is the Agent binary in the OCI image. This check only proves process
# liveness; control readiness remains the Controller's signed session concern.
kill -0 1
