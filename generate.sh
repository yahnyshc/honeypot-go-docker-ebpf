#!/bin/bash
cd src/generated
go generate 
cd ..
cd ..
go generate
