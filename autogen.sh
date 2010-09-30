#!/bin/bash

test -f ChangeLog || touch ChangeLog
autoreconf -iv
