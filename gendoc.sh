#!/bin/sh
(
cat <<EOF
// # Usage
//
EOF
./vex 2>&1 | sed 's,^,//	,g'
echo 'package main'
) >usage.go
