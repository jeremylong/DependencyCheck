#!/bin/sh
NVD_ROOT=$1/$(date -I)
JAR_PATH=$2/nist-data-mirror-1.0.0.jar
java -jar $JAR_PATH $NVD_ROOT
rm $NVD_ROOT/*.xml # D-C works directly with .gz files anyway.