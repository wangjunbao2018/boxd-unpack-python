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
python3 parse_proto.py  $1

# compile python files
#protoc -I=proto/ --python_out=python_proto proto/*.proto
python3 -m grpc_tools.protoc  --python_out=proto/ --grpc_python_out=proto/ -Iproto/ proto/*.proto

# cp
rm boxd_client/protocol/generated/*
cp proto/block*.py  proto/common*.py  proto/control*.py  proto/faucet*.py  proto/transaction*.py  proto/web*.py  boxd_client/protocol/generated/
touch boxd_client/protocol/generated/__init__.py


# run cmd
# sh build-python3.sh /Users/apple/workspace/box-hi/boxd