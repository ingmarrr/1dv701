#!/bin/bash

if [ "$#" -eq 1 ]; then
    if [ "$1" == "-c" ]; then
        rm -rf build
        for file in *.class; do
            rm "$file"
        done
        exit 0
    elif [ "$1" == "-d" ]; then
        # javac *.java
        javac App.java
        java App
        exit 0
    elif [ "$1" == "-b" ]; then
        if [ ! -d "./build" ]; then
            mkdir build
        fi
        # javac *.java -d ./build
        javac App.java -d ./build
        cd build
        java App
        exit 0
    else
        echo "Invalid arguments"
        exit 1
    fi
fi