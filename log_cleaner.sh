#!/bin/sh

[ -z "$2" ] && { echo "LogCleaner v0.1"; echo "Usage: $0 dir ip"; echo "Example: $0 /var/log/apache2 127.0.0.1"; exit 1; }
DIR=$1
IPADDR=$2
if [ -d $DIR ]; then
        echo "The following times the $IPADDR occurs in the files:"
        occurence=$(grep -r $IPADDR $DIR | wc -l | awk '{print $1}')
        echo $occurence
        if [ $occurence -gt 0 ]; then
        	read -p "Are you sure you want to delete? (y/n): " answer
 				if [ $answer = "y" ] || [ $answer = "Y" ]; then
 					for entry in "$DIR"/*
 						do
 							grep -v $IPADDR $entry > $entry._
 							mv $entry._ $entry
 						done
 				fi
        
        else
        	echo "Sorry, $IPADDR not found"
        	exit 1
        fi
else
        echo "It not a dir"
        exit 1
fi
