#!/usr/bin/env python3
"""T-156: turn corpus sessions into per-session window matrices for a given feature version, cached on disk.

`v1` is exactly the shipped `tunnelscope.leakage.attacker.window_features`. Other versions are registered here by the
experiments that test them; a version only reaches the product after an experiment says so.
"""
from __future__ import annotations

import hashlib
import os
import pickle
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from corpus import CACHE  # noqa: E402

CAP = 60            # windows kept per session (as EXP-19/20), seeded per session
MIN_WINDOWS = 3     # the product's floor: fewer windows -> "insufficient", never scored


def _v1(t, out, size):
    from tunnelscope.leakage.attacker import window_features
    return window_features(list(zip(t.tolist(), np.where(out, "out", "in").tolist(), size.tolist())))


VERSIONS = {"v1": _v1}


def register(name, fn):
    VERSIONS[name] = fn


def _one(args):
    version, sid, t, out, size = args
    w = VERSIONS[version](t, out, size)
    if len(w) > CAP:
        rng = np.random.default_rng(int(hashlib.sha256(sid.encode()).hexdigest()[:8], 16))
        w = [w[j] for j in sorted(rng.choice(len(w), CAP, replace=False))]
    return np.asarray(w, np.float32)


def windows(sessions, version="v1", workers=6):
    """-> list of float32 arrays, one per session (possibly with fewer than MIN_WINDOWS rows)."""
    CACHE.mkdir(parents=True, exist_ok=True)
    out = [None] * len(sessions)
    todo = []
    for i, s in enumerate(sessions):
        key = CACHE / "win" / version / (hashlib.sha256(f"{s.sid}|{len(s.t)}|{float(s.t[-1]) if len(s.t) else 0}".encode()).hexdigest()[:24] + ".npy")
        if key.exists():
            out[i] = np.load(key)
        else:
            todo.append((i, key))
    if todo:
        (CACHE / "win" / version).mkdir(parents=True, exist_ok=True)
        with ProcessPoolExecutor(workers) as ex:
            res = ex.map(_one, [(version, sessions[i].sid, sessions[i].t, sessions[i].out, sessions[i].size) for i, _ in todo],
                         chunksize=4)
            for (i, key), w in zip(todo, res):
                np.save(key, w)
                out[i] = w
    return out
