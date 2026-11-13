"""Names of the per-contract metadata variables in storage.

Kept apart from the driver so the native VM host can use them without
importing the storage engine (which itself loads the native module).
"""

SOURCE_KEY = "__source__"
XIAN_VM_V1_IR_KEY = "__xian_ir_v1__"
TYPE_KEY = "__type__"
AUTHOR_KEY = "__author__"
OWNER_KEY = "__owner__"
TIME_KEY = "__submitted__"
DEVELOPER_KEY = "__developer__"
DEPLOYER_KEY = "__deployer__"
INITIATOR_KEY = "__initiator__"
