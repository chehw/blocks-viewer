A bitcoin library and blocks viewer in C
======================

License
-------
[The MIT License (MIT)](https://opensource.org/licenses/MIT)


Dependencies
-------------

These dependencies are required:

    ----------------------------------------
    Library         |  Description
    ----------------|-----------------------
    gtk+-3.0        | GUI
    gnutls          | sha256 / ripemd160
    libsecp256k1    | crypto: sign / verify [link](https://github.com/bitcoin/bitcoin/tree/master/src/secp256k1)
    libgmp          | uint256 Arithmetic
    ----------------------------------------

Optional dependencies:

    ----------------------------------------
    Library         |  Description
    ----------------|-----------------------
    json-c          | json 
    libdb-5.3       | blocks.db and utxoes.db
    ----------------------------------------


## Build

### Linux / Debian 

#### install dependencies

    $ sudo apt-get install build-essential 
    $ sudo apt-get install libgmp-dev libgtk-3-dev 
    $ sudo apt-get install gnutls-dev
    
    $ cd /tmp && git clone https://github.com/bitcoin-core/secp256k1
    $ cd secp256k1 && ./autogen.sh
    $ ./configure
    $ make && sudo make install
    
    (optional)
    $ sudo apt-get install libdb5.3-dev libjson-c-dev 

#### build

    $ git clone https://github.com/chehw/blocks-viewer.git
    $ cd blocks-viewer
    $ make

#### run
    - copy block files (blk<nnnnn>.dat) to folder '`pwd`/blocks/' 
    - or make symbolic links to '`pwd`/blocks'

    $ bin/blocks-viewer

