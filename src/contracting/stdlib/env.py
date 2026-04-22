from xian_runtime_types.collections import exports as collection_exports
from xian_runtime_types.decimal import exports as decimal_exports
from xian_runtime_types.time import exports as time_exports

from contracting.stdlib.bridge.access import exports as access_exports
from contracting.stdlib.bridge.crypto import exports as crypto_exports
from contracting.stdlib.bridge.hashing import exports as hash_exports
from contracting.stdlib.bridge.imports import exports as imports_exports
from contracting.stdlib.bridge.orm import exports as orm_exports
from contracting.stdlib.bridge.random import exports as random_exports
from contracting.stdlib.bridge.zk import exports as zk_exports
from contracting.stdlib.builtins import exports as builtin_exports

# Contracts currently receive a flat stdlib namespace. Keep the export list
# explicit so changes to the contract-visible surface are easy to review.


def gather():
    env = {}

    env.update(builtin_exports)
    env.update(orm_exports)
    env.update(hash_exports)
    env.update(time_exports)
    env.update(random_exports)
    env.update(imports_exports)
    env.update(access_exports)
    env.update(decimal_exports)
    env.update(collection_exports)
    env.update(crypto_exports)
    env.update(zk_exports)

    return env
