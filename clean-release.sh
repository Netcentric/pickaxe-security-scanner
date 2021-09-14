#!/bin/bash

# Cleans up release.properties and backup files

read -p "Are you sure you want to remove release.properties and backup files [Y/n]: " agreed

if [ $agreed == 'Y' ]
then
	mvn release:clean
else
	echo "Release clean cancelled"
fi
