#!/bin/sh


files=$(find protob -maxdepth 1 -name '*.proto')
echo $files

for file in $files;do
  protoc -I=. --go_out=. $file
done

cp -r github.com/sisu-network/tss-lib/* ./
rm -rf github.com
