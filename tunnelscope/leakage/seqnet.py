"""Inference for EXP-52's sequence network, in NumPy only (no PyTorch in the product).

A 1D-CNN over one window's packets: direction, log2(size)/11 and log10(gap)/6, three convolution blocks (kernel 5, batch norm, ReLU),
masked mean and max pooling, one hidden layer, softmax over the eight traffic classes. The weights are trained by us with PyTorch
(`experiments/exp52-sequence-net/`) and stored as a NumPy `.npz`; this file reads them and runs the same arithmetic.

It is not wired into any finding, verdict or score. Nothing calls it unless a trained model file is shipped (that depends on EXP-52's
pre-registered result), and `tests/test_seqnet.py` checks it against the PyTorch network it mirrors.
"""
from __future__ import annotations

import numpy as np

L = 256                       # packets per window (EXP-52 PREREG section 4)
CLASSES = ["bulk", "email", "icmp", "interactive", "messaging", "video", "voip", "web"]
BN_EPS = 1e-5                 # torch.nn.BatchNorm1d default
_KERNEL, _PAD = 5, 2
_BLOCKS = 3


def encode(X: np.ndarray, lens: np.ndarray, use_gap: bool = True) -> tuple[np.ndarray, np.ndarray]:
    """Raw windows [n, L, 3] (direction +1/-1, log2(size)/11, raw gap seconds) and packet counts [n] -> input [n, 3, L], mask [n, L].
    The gap channel becomes log10(max(gap, 1e-6)) / 6 (first packet 0); with `use_gap` False it is zero."""
    X = np.array(X, np.float32)
    mask = np.arange(L)[None, :] < np.asarray(lens)[:, None]
    first = np.zeros_like(mask)
    first[:, 0] = True
    X[:, :, 2] = np.where(mask & ~first, np.log10(np.maximum(X[:, :, 2], 1e-6)) / 6.0, 0.0) if use_gap else 0.0
    X[~mask] = 0.0
    return np.ascontiguousarray(X.transpose(0, 2, 1)), mask.astype(np.float32)


def _conv_bn_relu(x: np.ndarray, w: np.ndarray, b: np.ndarray, gamma, beta, mean, var) -> np.ndarray:
    """x [n, C_in, L] -> [n, C_out, L]: Conv1d(kernel 5, padding 2) -> BatchNorm1d (inference) -> ReLU, as one matrix product."""
    n, c_in, length = x.shape
    xp = np.pad(x, ((0, 0), (0, 0), (_PAD, _PAD)))
    win = np.lib.stride_tricks.sliding_window_view(xp, _KERNEL, axis=2)           # [n, C_in, L, K]
    cols = win.transpose(0, 2, 1, 3).reshape(n * length, c_in * _KERNEL)           # rows: (window, position); cols: (channel, tap)
    scale = gamma / np.sqrt(var + BN_EPS)
    wf = (w.reshape(w.shape[0], -1) * scale[:, None]).T                            # BN folded into the weights
    bf = (b - mean) * scale + beta
    y = cols @ wf.astype(np.float32) + bf.astype(np.float32)                       # [n*L, C_out]
    return np.maximum(y, 0.0).reshape(n, length, -1).transpose(0, 2, 1)


class SeqNet:
    """Weights as a dict of NumPy arrays: `b{0,1,2}.{w,b,gamma,beta,mean,var}`, `h.{w,b}`, `o.{w,b}` (PyTorch layouts)."""

    def __init__(self, params: dict[str, np.ndarray]):
        self.p = {k: np.asarray(v, np.float32) for k, v in params.items()}
        for i in range(_BLOCKS):
            assert self.p[f"b{i}.w"].shape[2] == _KERNEL
        assert self.p["o.w"].shape[0] == len(CLASSES)

    @classmethod
    def load(cls, path: str) -> "SeqNet":
        with np.load(path, allow_pickle=False) as z:
            return cls({k: z[k] for k in z.files})

    def forward(self, x: np.ndarray, mask: np.ndarray) -> np.ndarray:
        """Logits [n, 8] for encoded windows x [n, 3, L] and mask [n, L]."""
        p = self.p
        for i in range(_BLOCKS):
            x = _conv_bn_relu(x, p[f"b{i}.w"], p[f"b{i}.b"], p[f"b{i}.gamma"], p[f"b{i}.beta"], p[f"b{i}.mean"], p[f"b{i}.var"])
        m = mask[:, None, :]
        mean = (x * m).sum(-1) / np.maximum(m.sum(-1), 1.0)
        mx = np.where(m == 0, -np.inf, x).max(-1)
        h = np.maximum(np.concatenate([mean, mx], 1) @ p["h.w"].T + p["h.b"], 0.0)
        return h @ p["o.w"].T + p["o.b"]

    def predict_proba(self, X: np.ndarray, lens: np.ndarray, use_gap: bool = True, batch: int = 512) -> np.ndarray:
        """Class probabilities [n, 8] for raw windows (see `encode`)."""
        out = []
        for i in range(0, len(X), batch):
            x, m = encode(X[i:i + batch], lens[i:i + batch], use_gap)
            z = self.forward(x, m)
            z = z - z.max(1, keepdims=True)
            e = np.exp(z)
            out.append(e / e.sum(1, keepdims=True))
        return np.concatenate(out) if out else np.zeros((0, len(CLASSES)), np.float32)


def params_from_torch_state(state: dict) -> dict[str, np.ndarray]:
    """A PyTorch `Net.state_dict()` (EXP-52's `netlib.make_net`) -> the arrays `SeqNet` reads. Used when exporting a trained model."""
    out = {}
    for i in range(_BLOCKS):
        s = f"b.{i}."
        out.update({f"b{i}.w": state[s + "c.weight"], f"b{i}.b": state[s + "c.bias"], f"b{i}.gamma": state[s + "n.weight"],
                    f"b{i}.beta": state[s + "n.bias"], f"b{i}.mean": state[s + "n.running_mean"], f"b{i}.var": state[s + "n.running_var"]})
    out.update({"h.w": state["h.weight"], "h.b": state["h.bias"], "o.w": state["o.weight"], "o.b": state["o.bias"]})
    return {k: np.asarray(v.detach().cpu().numpy() if hasattr(v, "detach") else v, np.float32) for k, v in out.items()}
