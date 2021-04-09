import hashlib
import enum


Algorithm = enum.Enum(
    'Algorithm', {
        name: name for name in hashlib.algorithms_guaranteed
    }
)
