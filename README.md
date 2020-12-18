# ZRE Raft: Proximity Chat over LAN

[![image](https://img.shields.io/pypi/v/zre_raft.svg)](https://pypi.python.org/pypi/zre_raft)
[![image](https://img.shields.io/travis/adsharma/zre_raft.svg)](https://travis-ci.com/adsharma/zre_raft)
[![Documentation Status](https://readthedocs.org/projects/zre-raft/badge/?version=latest)](https://zre-raft.readthedocs.io/en/latest/?badge=latest)


The idea is that there is no central server. Clients discover each other
using [ZRE](https://rfc.zeromq.org/spec/20/) - ZeroMQ Realtime
Exchange Protocol.

## Implementations

*   [Zyre](https://github.com/zeromq/zyre) (C++ and FFI to python)
*   [Pyre](https://github.com/zeromq/pyre) (Pure python)
*   [Gyre](https://github.com/zeromq/gyre) (Go)

This software was tested with pyre, but should work with zyre as well
in-theory.

## Installation

``` 
alias pip=pip3
# pyre needs special install command line 
pip install https://github.com/zeromq/pyre/archive/master.zip 
# rest
pip install -r requirements.txt
python3 setup.py install --user
~/.local/bin/zre_raft -n $CHATNAME
```

-   Free software: MIT license
-   Documentation: <https://zre-raft.readthedocs.io>.

## Consensus

After the basic chat functionality is working, this could be a useful
test bed to experiment with different consensus algorithms such as Raft
and Paxos for configuration.

This way, bad actors can't spoof and hijack chat sessions

## Features

-   Peer discovery on LAN
-   Notifications on joining/leaving
-   Basic chat
-   CLI using [prompt_toolkit](https://github.com/prompt-toolkit/python-prompt-toolkit)

## Credits

This package was created with
[Cookiecutter](https://github.com/audreyr/cookiecutter) and the
[audreyr/cookiecutter-pypackage](https://github.com/audreyr/cookiecutter-pypackage)
project template.
