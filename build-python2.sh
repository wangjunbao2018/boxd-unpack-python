#!/bin/sh

dir="proto"

# mkdir dir
if [ ! -d "$dir" ];then
	mkdir $dir
else
	if [ "`ls -A $dir`" = "" ]; then
  		echo "$DIRECTORY is indeed empty"
  		echo "$DIRECTORY is not empty"
		echo "$dir exists, please rebuild it"
		rm "$dir"/*
	fi
fi	

# get proto files 
python parse_proto.py  $1

# compile python files
#protoc -I=proto/ --python_out=python_proto proto/*.proto
 python -m grpc_tools.protoc  --python_out=proto/ --grpc_python_out=proto/ -Iproto/ proto/*.proto


