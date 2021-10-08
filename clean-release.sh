#!/bin/bash
# (C) Copyright 2020 Netcentric - a Cognizant Digital Business. All rights reserved. This program
# and the accompanying materials are made available under the terms of the
# Eclipse Public License v1.0 which accompanies this distribution, and is available
# at http://www.eclipse.org/legal/epl-v10.html

# Cleans up release.properties and backup files

read -p "Are you sure you want to remove release.properties and backup files [Y/n]: " agreed

if [ $agreed == 'Y' ]
then
	mvn release:clean
else
	echo "Release clean cancelled"
fi
