"""EXP-52 P52-7: the NumPy inference reproduces the PyTorch network it mirrors (probabilities within 1e-4) and is fast enough.

PyTorch is a training-only dependency, so these tests are skipped where it is not installed."""
import pathlib
import sys
import time

import numpy as np
import pytest

from tunnelscope.leakage import seqnet

torch = pytest.importorskip("torch")
EXP = pathlib.Path(__file__).resolve().parents[1] / "experiments" / "exp52-sequence-net"
sys.path.insert(0, str(EXP))
import netlib  # noqa: E402


def _random_trained_like_net(seed=0):
    """The real network with non-trivial weights AND batch-norm statistics, as a trained one has."""
    torch.manual_seed(seed)
    net = netlib.make_net()
    with torch.no_grad():
        for m in net.modules():
            if isinstance(m, torch.nn.BatchNorm1d):
                m.running_mean.normal_(0, 0.3); m.running_var.uniform_(0.002, 2.0)
                m.weight.uniform_(0.5, 1.5); m.bias.normal_(0, 0.2)
    return net.eval()


def _windows(n, seed=1):
    rng = np.random.default_rng(seed)
    lens = rng.integers(3, seqnet.L + 1, n)
    X = np.zeros((n, seqnet.L, 3), np.float32)
    for i, k in enumerate(lens):
        X[i, :k, 0] = rng.choice([-1.0, 1.0], k)
        X[i, :k, 1] = np.log2(rng.integers(40, 1500, k)) / 11.0
        X[i, 1:k, 2] = rng.lognormal(-5, 2, k - 1)               # gaps in seconds, from microseconds to seconds
    return X, lens


def test_encode_matches_the_training_encoding():
    X, lens = _windows(64)
    for use_gap in (True, False):
        a, ma = seqnet.encode(X, lens, use_gap)
        b, mb = netlib.encode(X, lens, use_gap)
        assert np.allclose(a, b, atol=1e-6) and np.array_equal(ma, mb)


@pytest.mark.parametrize("use_gap", [True, False])
def test_probabilities_match_pytorch_within_1e_4(use_gap):
    net = _random_trained_like_net()
    sn = seqnet.SeqNet(seqnet.params_from_torch_state(net.state_dict()))
    X, lens = _windows(200)
    ref = netlib.predict(net, X, lens, use_gap)
    got = sn.predict_proba(X, lens, use_gap)
    assert got.shape == ref.shape == (200, 8)
    assert np.allclose(got.sum(1), 1.0, atol=1e-5)
    assert np.abs(got - ref).max() < 1e-4, np.abs(got - ref).max()
    assert (got.argmax(1) == ref.argmax(1)).all()


def test_a_short_window_is_not_changed_by_what_sits_in_its_padding():
    """Padding must not leak into the pooled features: garbage after `lens` changes nothing."""
    net = _random_trained_like_net(3)
    sn = seqnet.SeqNet(seqnet.params_from_torch_state(net.state_dict()))
    X, lens = _windows(20, seed=5)
    dirty = X.copy()
    for i, k in enumerate(lens):
        dirty[i, k:] = np.random.default_rng(i).normal(size=(seqnet.L - k, 3))
    assert np.allclose(sn.predict_proba(X, lens), sn.predict_proba(dirty, lens), atol=1e-6)


def test_weights_round_trip_through_npz(tmp_path):
    net = _random_trained_like_net(4)
    params = seqnet.params_from_torch_state(net.state_dict())
    np.savez(tmp_path / "m.npz", **params)
    X, lens = _windows(30, seed=6)
    a = seqnet.SeqNet(params).predict_proba(X, lens)
    b = seqnet.SeqNet.load(str(tmp_path / "m.npz")).predict_proba(X, lens)
    assert np.array_equal(a, b)
    assert sum(v.nbytes for v in params.values()) < 5_000_000       # P52-7: model file <= 5 MB


def test_scoring_one_window_takes_under_5_ms():
    net = _random_trained_like_net(7)
    sn = seqnet.SeqNet(seqnet.params_from_torch_state(net.state_dict()))
    X, lens = _windows(64, seed=8)
    sn.predict_proba(X[:8], lens[:8])                                 # warm up
    t0 = time.perf_counter()
    for _ in range(3):
        sn.predict_proba(X, lens, batch=64)
    per_window_ms = (time.perf_counter() - t0) / (3 * len(X)) * 1000
    print(f"{per_window_ms:.2f} ms per 2-s window")
    assert per_window_ms < 5.0, per_window_ms
