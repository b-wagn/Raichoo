Implementation of Rai-Choo!
===========================

This repository contains a prototypical implementation of the [Rai-Choo! blind signature scheme](https://eprint.iacr.org/2022/1350.pdf).


## Dependencies
Before compilation, first ensure that the `gmp` dependency is installed.
For that, install `libgmp3-dev` using 

	sudo apt-get install libgmp3-dev 

Install the `mcl` dependency.
A simple way to do that is to clone the `mcl` repository via

	git clone https://github.com/alinush/go-mcl.git

and then use

	cd go-mcl
	./scripts/install-deps.sh
	
Additionally, you need the `openssl` library. 
You can install it using

	sudo apt-get install libssl-dev

## Parameter Selection (Optional)
If you want to use/test parameters different than the standard parameters (N=8,K=54), then go to file `src/parameters.hpp` and change the line `#define MEDIUM_N_PARS` to `#define LOW_N_PARS` (N=4,K=80) or `#define HIGH_N_PARS` (N=32,K=33).

## Building
Run 
	
	cd build
	make all

Then, there should be an executable file `Raichoo` in this directory.


## Licence
BSD-3-Clause licence https://opensource.org/licenses/BSD-3-Clause
