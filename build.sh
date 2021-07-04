#!/bin/bash

git submodule update --init --recursive

git submodule foreach git checkout master

git submodule foreach git pull

xcodebuild -jobs 1 -configuration Debug
xcodebuild -jobs 1 -configuration Release
