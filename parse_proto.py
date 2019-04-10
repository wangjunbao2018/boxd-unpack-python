#!/usr/bin/env python3

import sys
import os
import os.path

import shutil


# setting
rootdir = "/Users/apple/workspace/box-hi/boxd"

if  len(sys.argv) < 2:
    print ("Usage: python parse_proto.py  boxd_path")
    sys.exit(0)


if "/boxd" not in rootdir:
	print("rootdir is not boxd dir")
	sys.exit(0)
rootdir = sys.argv[1]
print("rootdir:" + rootdir)


filter = ["core/pb", "rpc/pb"]
filter2 = ["trie.proto"]
proto_files = {}


# get proto files
for parent, dirnames, filenames in os.walk(rootdir):
	# it doesn't need to process dir here
	#for dirname in dirnames:
	#	print parent, dirname
	
	# process file
	for filename in filenames:
		if ".proto" in filename:
			for item in filter:
				if item in parent:
                                        if filename in filter2:
                                            continue
                                        else:
                                            proto_files[filename] = parent + "/" + filename

target_dir = os.getcwd() + "/" + "proto/"
for proto_name, proto_file in proto_files.items():
	shutil.copyfile(proto_file, target_dir + proto_name )


	

def process_file(dir, name):
	f = dir + "/" + name
	count = 0
	lines = []
	with open(f, "r") as ff:
		
		isIngore = False
		annotation_line_count = 0
		for line in ff:
			count = count + 1

			if  line.strip().startswith("rpc") and line.strip().endswith("{"):
				isIngore = True
				lines.append("\n")
				lines.append( line.replace("{", ";"))
			if not isIngore:
				if line.strip().startswith("package"):
					lines.append(line)
					lines.append("\n")
				elif line.strip().startswith("import"):
					if "github.com/BOXFoundation" in line:
						lines.append(line.replace("github.com/BOXFoundation/boxd/core/pb/", ""))
					elif "google/api/annotations.proto" in line:
						lines.append("//" + line)
					else:	
						lines.append( line)
				else:
					lines.append( line)
			else:
				annotation_line_count += 1
				lines.append( "//" + line)
				if annotation_line_count >= 6:
					annotation_line_count = 0
					isIngore = False					 	
				
				
		ff.close()

	with open(f, "w") as ff:
		for line in lines:
			ff.write(line)
		ff.close()
		
for name in os.listdir(target_dir):
	process_file(target_dir, name)



if __name__ == "__main__":
	print("hi")
