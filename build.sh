#!/bin/sh

mkdir BUILD
cp -r src/* BUILD/
cp requirements.txt BUILD/
cd BUILD
../install_deps.sh
rm requirements.txt
zip -r lambda.zip *
mv lambda.zip ..
