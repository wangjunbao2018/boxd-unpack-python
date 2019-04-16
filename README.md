# boxd-sdk-python

## Installation

```pip install boxd-client```

## QuickStart

```
from boxd_client.boxd_client import BoxdClient
boxd = BoxdClient("39.97.169.1", 19111)

# get current block height
height_resp = boxd.get_block_height()

# get block hash
block_hash_resp = boxd.get_block_hash(height_resp.height)

# get block
block_resp = boxd.get_block(block_hash_resp.hash)
print (block_resp)

```

## FQA

### When I run `pip install boxd-client`, I got some errors on `Ubuntu 18.04.1 LTS`.

   Run `sudo apt-get install libsecp256k1-dev` first.

