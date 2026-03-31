from contracting.storage.driver import Driver
from contracting.execution.runtime import rt
from contracting import constants
from contracting.stdlib.bridge.decimal import ContractingDecimal
from contracting.storage.encoder import encode_kv

driver = rt.env.get("__Driver") or Driver()
EVENT_ALLOWED_TYPES = (str, int, float, bool, ContractingDecimal)


def indexed(*types):
    assert len(types) > 0, "indexed() requires at least one type."

    if len(types) == 1 and isinstance(types[0], tuple):
        types = types[0]

    return {
        "type": types[0] if len(types) == 1 else tuple(types),
        "idx": True,
    }


class Datum:
    def __init__(self, contract, name, driver: Driver):
        self._driver = driver
        self._key = self._driver.make_key(contract, name)


class Variable(Datum):
    def __init__(self, contract, name, driver: Driver = driver, t=None, default_value=None):
        self._type = None

        if isinstance(t, type):
            self._type = t

        self._default_value = default_value

        super().__init__(contract, name, driver=driver)

    def set(self, value):
        if self._type is not None and value is not None:
            assert isinstance(value, self._type), (
              f'Wrong type passed to variable! '
              f'Expected {self._type}, got {type(value)}.'
            )

        self._driver.set(self._key, value, True)

    def get(self):
        value = self._driver.get(self._key)
        if value is None:
            return self._default_value
        return value

class Hash(Datum):
    def __init__(self, contract, name, driver: Driver = driver, default_value=None):
        super().__init__(contract, name, driver=driver)
        self._delimiter = constants.DELIMITER
        self._default_value = default_value

    def _set(self, key, value):
        self._driver.set(f"{self._key}{self._delimiter}{key}", value, True)

    def _get(self, item):
        value = self._driver.get(f"{self._key}{self._delimiter}{item}")

        # Add Python defaultdict behavior for easier smart contracting
        if value is None:
            value = self._default_value

        if type(value) == float or type(value) == ContractingDecimal:
            return ContractingDecimal(str(value))

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
                assert constants.INDEX_SEPARATOR not in k, "Illegal separator in key."

                new_key_str += f"{k}{self._delimiter}"

            key = new_key_str[: -len(self._delimiter)]
        else:
            key = str(key)

            assert constants.DELIMITER not in key, "Illegal delimiter in key."
            assert constants.INDEX_SEPARATOR not in key, "Illegal separator in key."

        assert (
            len(key) <= constants.MAX_KEY_SIZE
        ), f"Key is too long ({len(key)}). Max is {constants.MAX_KEY_SIZE}."
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
        self, contract, name, foreign_contract, foreign_name, driver: Driver = driver
    ):
        super().__init__(contract, name, driver=driver)
        self._key = self._driver.make_key(foreign_contract, foreign_name)

    def set(self, value):
        raise ReferenceError


class ForeignHash(Hash):
    def __init__(
        self, contract, name, foreign_contract, foreign_name, driver: Driver = driver
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
        *args,
        contract=None,
        name=None,
        event=None,
        params=None,
        driver: Driver = driver,
    ):
        contract, name, event, params = self._resolve_init_args(
            args=args,
            contract=contract,
            name=name,
            event=event,
            params=params,
        )

        self._contract = contract or rt.context.this or "__event__"
        self._name = name or event
        super().__init__(self._contract, self._name, driver=driver)

        self._event = self._validate_event_name(event)
        self._params = self._normalize_params(params)

    @staticmethod
    def _resolve_init_args(args, contract, name, event, params):
        if len(args) == 0:
            pass
        elif len(args) == 1 and event is None and params is not None:
            event = args[0]
        elif len(args) == 2:
            if event is None and params is None:
                event, params = args
            elif event is not None and params is not None and contract is None and name is None:
                contract, name = args
            else:
                raise TypeError(
                    "Invalid LogEvent arguments. Use LogEvent(event, params, *, contract=..., name=...)."
                )
        elif len(args) == 4 and all(value is None for value in (contract, name, event, params)):
            contract, name, event, params = args
        else:
            raise TypeError(
                "Invalid LogEvent arguments. Use LogEvent(event, params, *, contract=..., name=...)."
            )

        if event is None or params is None:
            raise TypeError("LogEvent requires both event and params.")

        return contract, name, event, params

    @staticmethod
    def _validate_event_name(event):
        assert isinstance(event, str), "Event name must be a string."
        assert event.strip(), "Event name must not be empty."
        return event

    @classmethod
    def _normalize_types(cls, arg_name, type_spec):
        if isinstance(type_spec, tuple):
            normalized_types = type_spec
        elif isinstance(type_spec, type):
            normalized_types = (type_spec,)
        else:
            raise AssertionError(
                f"Argument {arg_name} type spec must be a type, tuple of types, "
                "or a dict with a 'type' field."
            )

        assert len(normalized_types) > 0, f"Argument {arg_name} must declare at least one type."
        assert all(isinstance(t, type) for t in normalized_types), (
            f"Argument {arg_name} type spec must contain only types."
        )
        assert all(issubclass(t, EVENT_ALLOWED_TYPES) for t in normalized_types), (
            "Each type in args must be str, int, float, decimal or bool."
        )

        return normalized_types

    @classmethod
    def _normalize_param(cls, arg_name, param):
        if isinstance(param, dict):
            extra_keys = set(param.keys()) - {"type", "idx"}
            assert not extra_keys, (
                f"Argument {arg_name} has unsupported schema keys: {sorted(extra_keys)}."
            )
            assert "type" in param, f"Argument {arg_name} must declare a type."
            idx = param.get("idx", False)
            assert isinstance(idx, bool), f"Argument {arg_name} idx must be a boolean."
            type_spec = param["type"]
        else:
            idx = False
            type_spec = param

        return {
            "type": cls._normalize_types(arg_name, type_spec),
            "idx": idx,
        }

    @classmethod
    def _normalize_params(cls, params):
        assert isinstance(params, dict), "Args must be a dictionary."
        assert len(params) > 0, "Args must have at least one argument."

        normalized = {}
        for arg_name, param in params.items():
            assert isinstance(arg_name, str), "Argument names must be strings."
            assert arg_name.strip(), "Argument names must not be empty."
            normalized[arg_name] = cls._normalize_param(arg_name, param)

        indexed_args_count = sum(1 for arg in normalized.values() if arg["idx"])
        assert indexed_args_count <= 3, "Args must have at most three indexed arguments."

        return normalized


    def write_event(self, event_data):
        assert isinstance(event_data, dict), "Event data must be a dictionary."
        caller = rt.context.caller
        signer = rt.context.signer
        assert len(event_data) == len(
            self._params
        ), "Data must have the same number of arguments as specified in the event."

        # Check for unexpected arguments
        for arg in event_data:
            assert (
                arg in self._params
            ), f"Unexpected argument {arg} in the data dictionary."

        # Check for missing and type-mismatched arguments
        for arg in self._params:
            assert (
                arg in event_data
            ), f"Argument {arg} is missing from the data dictionary."

            # Check the type of the argument
            assert isinstance(event_data[arg], self._params[arg]["type"]), (
                f"Argument {arg} is the wrong type! "
                f"Expected {self._params[arg]['type']}, got {type(event_data[arg])}."
            )

            # Check the size of the argument
            value_size = len(str(event_data[arg]).encode("utf-8"))
            assert (
                value_size <= 1024
            ), f"Argument {arg} is too large ({value_size} bytes). Max is 1024 bytes."
        
        event = {
            "contract": self._contract,
            "event": self._event,
            "signer": signer,
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
            encoded = encode_kv(arg, value)
            rt.deduct_write(*encoded)
        for arg, value in event["data"].items():
            encoded = encode_kv(arg, value)
            rt.deduct_write(*encoded)

        self._driver.set_event(event)


    def __call__(self, data):
        self.write_event(data)
