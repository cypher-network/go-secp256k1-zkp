deps: deps-secp256k1-zkp

deps-secp256k1-zkp:
	cd ./secp256k1-zkp && ./autogen.sh && ./configure --enable-module-recovery  --enable-module-ecdh --enable-module-commitment --enable-module-rangeproof --enable-module-bulletproof --enable-module-generator --enable-module-mlsag --enable-experimental --enable-endomorphism && make -j4 && cd ..