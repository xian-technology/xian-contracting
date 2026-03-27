from copy import deepcopy

from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.encoding import encode_kv

from contracting import constants
from contracting.execution.runtime import rt
from contracting.storage.driver import Driver

_MISSING = object()


def _copy_mutable(value):
    if isinstance(value, (list, dict)):
        return deepcopy(value)
    return value


class Datum:
    def __init__(self, contract, name, driver: Driver):
        self._driver = driver
        self._key = self._driver.make_key(contract, name)


class Variable(Datum):
    def __init__(
        self,
        contract,
        name,
        driver: Driver | None = None,
        t=None,
        default_value=None,
    ):
        self._type = None

        if isinstance(t, type):
            self._type = t

        self._default_value = default_value

        resolved_driver = driver or rt.env.get("__Driver") or Driver()
        super().__init__(contract, name, driver=resolved_driver)

    def set(self, value):
        if self._type is not None and value is not None:
            assert isinstance(value, self._type), (
                f"Wrong type passed to variable! "
                f"Expected {self._type}, got {type(value)}."
            )

        self._driver.set(self._key, value, True)

    def get(self):
        value = self._driver.get(self._key)
        if value is None:
            return _copy_mutable(self._default_value)
        return _copy_mutable(value)

    def _get_mutable_value(self, method_name: str):
        value = self.get()
        assert isinstance(value, (list, dict)), (
            f"Variable.{method_name}() requires the stored value "
            f"to be a list or dict."
        )
        return value

    def _get_list_value(self, method_name: str):
        value = self.get()
        assert isinstance(value, list), (
            f"Variable.{method_name}() requires the stored value to be a list."
        )
        return value

    def _get_dict_value(self, method_name: str):
        value = self.get()
        assert isinstance(value, dict), (
            f"Variable.{method_name}() requires the stored value to be a dict."
        )
        return value

    def __getitem__(self, key):
        value = self._get_mutable_value("__getitem__")
        return _copy_mutable(value[key])

    def __setitem__(self, key, value):
        current = self._get_mutable_value("__setitem__")
        current[key] = value
        self.set(current)

    def __delitem__(self, key):
        current = self._get_mutable_value("__delitem__")
        del current[key]
        self.set(current)

    def __contains__(self, item):
        current = self._get_mutable_value("__contains__")
        return item in current

    def __len__(self):
        current = self._get_mutable_value("__len__")
        return len(current)

    def update(self, other: dict):
        current = self._get_dict_value("update")
        assert isinstance(other, dict), (
            "Variable.update() requires a dict argument."
        )
        current.update(other)
        self.set(current)

    def append(self, value):
        current = self._get_list_value("append")
        current.append(value)
        self.set(current)

    def extend(self, values):
        current = self._get_list_value("extend")
        assert isinstance(values, list), (
            "Variable.extend() requires a list argument."
        )
        current.extend(values)
        self.set(current)

    def insert(self, index: int, value):
        current = self._get_list_value("insert")
        current.insert(index, value)
        self.set(current)

    def remove(self, value):
        current = self._get_list_value("remove")
        current.remove(value)
        self.set(current)

    def clear(self):
        current = self._get_mutable_value("clear")
        current.clear()
        self.set(current)

    def pop(self, key=_MISSING, default=_MISSING):
        current = self._get_mutable_value("pop")

        if isinstance(current, dict):
            assert key is not _MISSING, (
                "Variable.pop() requires a key for dict values."
            )
            if default is _MISSING:
                value = current.pop(key)
            else:
                value = current.pop(key, default)
        else:
            assert default is _MISSING, (
                "Variable.pop() does not accept a default for list values."
            )
            if key is _MISSING:
                key = -1
            value = current.pop(key)

        self.set(current)
        return _copy_mutable(value)


class Hash(Datum):
    def __init__(
        self,
        contract,
        name,
        driver: Driver | None = None,
        default_value=None,
    ):
        resolved_driver = driver or rt.env.get("__Driver") or Driver()
        super().__init__(contract, name, driver=resolved_driver)
        self._delimiter = constants.DELIMITER
        self._default_value = default_value

    def _set(self, key, value):
        self._driver.set(f"{self._key}{self._delimiter}{key}", value, True)

    def _get(self, item):
        value = self._driver.get(f"{self._key}{self._delimiter}{item}")

        # Add Python defaultdict behavior for easier smart contracting
        if value is None:
            value = self._default_value

        if isinstance(value, float | ContractingDecimal):
            return ContractingDecimal(str(value))
        # Return a defensive copy for mutable structures to prevent in-place
        # mutations from affecting cached objects in the driver.
        if isinstance(value, (list, dict)):
            return deepcopy(value)
        return value

    def _validate_key(self, key):
        if isinstance(key, tuple):
            assert len(key) <= constants.MAX_HASH_DIMENSIONS, (
                f"Too many dimensions ({len(key)}) for hash. "
                f"Max is {constants.MAX_HASH_DIMENSIONS}"
            )

            new_key_str = ""
            for k in key:
                assert not isinstance(k, slice), "Slices prohibited in hashes."

                k = str(k)

                assert constants.DELIMITER not in k, "Illegal delimiter in key."
                assert constants.INDEX_SEPARATOR not in k, (
                    "Illegal separator in key."
                )

                new_key_str += f"{k}{self._delimiter}"

            key = new_key_str[: -len(self._delimiter)]
        else:
            key = str(key)

            assert constants.DELIMITER not in key, "Illegal delimiter in key."
            assert constants.INDEX_SEPARATOR not in key, (
                "Illegal separator in key."
            )

        assert len(key) <= constants.MAX_KEY_SIZE, (
            f"Key is too long ({len(key)}). Max is {constants.MAX_KEY_SIZE}."
        )
        return key

    def _prefix_for_args(self, args):
        multi = self._validate_key(args)
        prefix = f"{self._key}{self._delimiter}"
        if multi != "":
            prefix += f"{multi}{self._delimiter}"

        return prefix

    def all(self, *args):
        prefix = self._prefix_for_args(args)
        return self._driver.values(prefix=prefix)

    def _items(self, *args):
        prefix = self._prefix_for_args(args)
        return self._driver.items(prefix=prefix)

    def clear(self, *args):
        kvs = self._items(*args)

        for k in kvs.keys():
            self._driver.delete(k)

    def __setitem__(self, key, value):
        # handle multiple hashes differently
        key = self._validate_key(key)
        self._set(key, value)

    def __getitem__(self, key):
        key = self._validate_key(key)
        return self._get(key)

    def __contains__(self, key):
        raise Exception('Cannot use "in" with a Hash.')


class ForeignVariable(Variable):
    def __init__(
        self,
        contract,
        name,
        foreign_contract,
        foreign_name,
        driver: Driver | None = None,
    ):
        super().__init__(contract, name, driver=driver)
        self._key = self._driver.make_key(foreign_contract, foreign_name)

    def set(self, value):
        raise ReferenceError


class ForeignHash(Hash):
    def __init__(
        self,
        contract,
        name,
        foreign_contract,
        foreign_name,
        driver: Driver | None = None,
    ):
        super().__init__(contract, name, driver=driver)
        self._key = self._driver.make_key(foreign_contract, foreign_name)

    def _set(self, key, value):
        raise ReferenceError

    def __setitem__(self, key, value):
        raise ReferenceError

    def __getitem__(self, item):
        return super().__getitem__(item)

    def clear(self, *args):
        raise Exception("Cannot write with a ForeignHash.")


class LogEvent(Datum):
    """
    TODO
    - Break validation into smaller functions
    - Add checks for use of illegal types and argument names (See Hash checks.)
    """

    def __init__(
        self,
        contract,
        name,
        event,
        params,
        driver: Driver | None = None,
    ):
        self._driver = driver or rt.env.get("__Driver") or Driver()
        self._params = params
        self._event = event
        self._signer = rt.context.signer

        assert isinstance(params, dict), "Args must be a dictionary."
        assert len(params) > 0, "Args must have at least one argument."
        # Check for indexed arguments with a maximum of three
        indexed_args_count = sum(
            1 for arg in params.values() if arg.get("idx", False)
        )
        assert indexed_args_count <= 3, (
            "Args must have at most three indexed arguments."
        )
        for param in params.values():
            if not isinstance(param["type"], tuple):
                param["type"] = (param["type"],)

            assert all(
                issubclass(t, (str, int, float, bool, ContractingDecimal))
                for t in param["type"]
            ), "Each type in args must be str, int, float, decimal or bool."

    def write_event(self, event_data):
        contract = rt.context.this
        caller = rt.context.caller
        assert len(event_data) == len(self._params), (
            "Event Data must have the same number of arguments as specified in the event."
        )

        # Check for unexpected arguments
        for arg in event_data:
            assert arg in self._params, (
                f"Unexpected argument {arg} in the data dictionary."
            )

        # Check for missing and type-mismatched arguments
        for arg in self._params:
            assert arg in event_data, (
                f"Argument {arg} is missing from the data dictionary."
            )

            # Check the type of the argument
            assert isinstance(event_data[arg], self._params[arg]["type"]), (
                f"Argument {arg} is the wrong type! "
                f"Expected {self._params[arg]['type']}, got {type(event_data[arg])}."
            )

            # Check the size of the argument
            value_size = len(str(event_data[arg]).encode("utf-8"))
            assert value_size <= 1024, (
                f"Argument {arg} is too large ({value_size} bytes). Max is 1024 bytes."
            )

        event = {
            "contract": contract,
            "event": self._event,
            "signer": self._signer,
            "caller": caller,
            "data_indexed": {
                arg: event_data[arg]
                for arg in self._params
                if self._params[arg].get("idx", False)
            },
            "data": {
                arg: event_data[arg]
                for arg in self._params
                if not self._params[arg].get("idx", False)
            },
        }

        for arg, value in event["data_indexed"].items():
            assert isinstance(value, self._params[arg]["type"]), (
                f"Indexed argument {arg} is the wrong type! Expected {self._params[arg]['type']}, got {type(value)}."
            )
            encoded = encode_kv(arg, value)
            rt.deduct_write(*encoded)
        for arg, value in event["data"].items():
            assert isinstance(value, self._params[arg]["type"]), (
                f"Non-indexed argument {arg} is the wrong type! Expected {self._params[arg]['type']}, got {type(value)}."
            )
            encoded = encode_kv(arg, value)
            rt.deduct_write(*encoded)

        self._driver.set_event(event)

    def __call__(self, data):
        self.write_event(data)
