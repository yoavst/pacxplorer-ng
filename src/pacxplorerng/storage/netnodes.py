__all__ = ["PickleNetNode"]

import pickle
from collections.abc import Callable
from typing import TypeVar

from netnode import Netnode

T = TypeVar("T")


class PickleNetNode(Netnode):
    """A NetNode subclass that uses pickle for encoding and decoding data."""

    @staticmethod
    def _encode(data):
        return pickle.dumps(data)

    @staticmethod
    def _decode(data):
        return pickle.loads(data)  # noqa: S301

    def get_or(self, key: str, func: Callable[[], T]) -> T:
        """
        Get the value associated with the key, or compute it using the provided function if it does not exist.

        :param key: The key to look up in the NetNode.
        :param func: A callable that computes the value if the key does not exist.
        :return: The value associated with the key.
        """
        try:
            return self[key]
        except KeyError:
            value = func()
            self[key] = value
            return value
