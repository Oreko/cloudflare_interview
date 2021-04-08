# cloudflare_interview

# Compiling
All compilation tests have been done on a linux environment using gcc/g++ 10.2.0

## To compile:
cd build
cmake ..
make install

## To run:
bin/WVOPRF

The WVOPRF executable is built off of main.cpp and runs a simple test to make sure that the outputs of the OPRF are consistent from the server and client view.