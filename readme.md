Implementation of Rai-Choo!
===========================

This repository contains a prototypical implementation of the Rai-Choo! blind signature scheme.


## Dependencies

Before compilation, install the `mcl` dependency.
A simple way to do that is to clone the `mcl` repository via

	git clone https://github.com/alinush/go-mcl.git

and then use

	cd go-mcl
	./scripts/install-deps.sh
	
Additionally, you need the `openssl` library. 
You can install it using

	sudo apt-get install libssl-dev

## Building
Run 
	
	cd build
	make all

Then, there should be an executable file `Raichoo` in this directory.


## Licence
BSD-3-Clause licence https://opensource.org/licenses/BSD-3-Clause
