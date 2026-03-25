import hashlib
from contextvars import ContextVar
from dataclasses import dataclass, field
from types import ModuleType

from contracting.execution.runtime import rt


@dataclass
class DeterministicRandom:
    seed_material: str
    counter: int = 0
    buffer: bytearray = field(default_factory=bytearray)

    def _refill(self) -> None:
        digest = hashlib.sha3_256(
            f"{self.seed_material}|{self.counter}".encode("utf-8")
        ).digest()
        self.counter += 1
        self.buffer.extend(digest)

    def getrandbits(self, k: int) -> int:
        if k < 0:
            raise ValueError("number of bits must be non-negative")
        if k == 0:
            return 0

        byte_count = (k + 7) // 8
        while len(self.buffer) < byte_count:
            self._refill()

        chunk = bytes(self.buffer[:byte_count])
        del self.buffer[:byte_count]

        value = int.from_bytes(chunk, "big")
        extra_bits = (byte_count * 8) - k
        if extra_bits:
            value >>= extra_bits
        return value

    def randbelow(self, upper: int) -> int:
        if upper <= 0:
            raise ValueError("upper bound must be positive")

        bit_count = (upper - 1).bit_length()
        while True:
            candidate = self.getrandbits(bit_count)
            if candidate < upper:
                return candidate


_RANDOM_STATE: ContextVar[DeterministicRandom | None] = ContextVar(
    "contracting_random_state",
    default=None,
)


def clear_random_state() -> None:
    _RANDOM_STATE.set(None)


def _current_random() -> DeterministicRandom:
    state = _RANDOM_STATE.get()
    assert state is not None, "Random state not seeded. Call seed()."
    return state


def _seed_material(aux_salt=None) -> str:
    parts = [
        f"chain_id={rt.env.get('chain_id') or ''}",
        f"block_num={rt.env.get('block_num') or 0}",
        f"block_hash={rt.env.get('block_hash') or '0'}",
        f"input_hash={rt.env.get('__input_hash') or '0'}",
    ]

    if aux_salt is not None:
        parts.append(f"aux_salt={aux_salt}")

    return "|".join(parts)


def seed(aux_salt=None):
    _RANDOM_STATE.set(DeterministicRandom(_seed_material(aux_salt)))


def getrandbits(k):
    return _current_random().getrandbits(k)


def shuffle(items):
    rng = _current_random()
    for idx in range(len(items) - 1, 0, -1):
        swap_idx = rng.randbelow(idx + 1)
        items[idx], items[swap_idx] = items[swap_idx], items[idx]


def randrange(k):
    return _current_random().randbelow(k)


def randint(a, b):
    if a > b:
        raise ValueError("empty range for randint()")
    return a + _current_random().randbelow((b - a) + 1)


def choice(items):
    if len(items) == 0:
        raise IndexError("Cannot choose from an empty sequence")
    return items[_current_random().randbelow(len(items))]


def choices(items, k):
    if k < 0:
        raise ValueError("number of choices must be non-negative")
    return [choice(items) for _ in range(k)]


random_module = ModuleType("random")
random_module.seed = seed
random_module.shuffle = shuffle
random_module.getrandbits = getrandbits
random_module.randrange = randrange
random_module.randint = randint
random_module.choice = choice
random_module.choices = choices

exports = {"random": random_module}
