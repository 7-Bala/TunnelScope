"""EXP-52's network (PREREG sections 4 and 5), with no dependency on the rest of the repository, so the same file runs on
this Mac and on a Colab GPU. `analyze.py` imports it; `colab_train.py` uploads it next to the data.

Everything here is fixed by the pre-registration: the input encoding, the 1D-CNN, the optimiser, the early stopping, the
per-window class weights, the one gap-scaled augmented copy of each training window, three seeds."""
from __future__ import annotations

import numpy as np

CLASSES = ["bulk", "email", "icmp", "interactive", "messaging", "video", "voip", "web"]
L = 256                       # packets per window seen by the network (PREREG section 4)
SEEDS = (0, 1, 2)
EPOCHS, PATIENCE, BATCH, LR = 30, 5, 256, 1e-3
SEEDS = (0, 1, 2)


def encode(X, lens, use_gap=True, scale=None):
    """Raw windows -> network input [n, 3, L] and mask [n, L]. Gap: log10(max(gap * scale, 1e-6)) / 6, first packet 0."""
    X = X.copy()
    mask = np.arange(L)[None, :] < lens[:, None]
    g = X[:, :, 2] * (scale[:, None] if scale is not None else 1.0)
    first = np.zeros_like(mask); first[:, 0] = True
    X[:, :, 2] = np.where(mask & ~first, np.log10(np.maximum(g, 1e-6)) / 6.0, 0.0) if use_gap else 0.0
    X[~mask] = 0.0
    return np.ascontiguousarray(X.transpose(0, 2, 1)), mask.astype(np.float32)


# ------------------------------------------------------------------ the network (PREREG section 5)
def make_net():
    import torch
    from torch import nn

    class Block(nn.Module):
        def __init__(self, a, b):
            super().__init__()
            self.c, self.n = nn.Conv1d(a, b, 5, padding=2), nn.BatchNorm1d(b)

        def forward(self, x):
            return torch.relu(self.n(self.c(x)))

    class Net(nn.Module):
        def __init__(self):
            super().__init__()
            self.b = nn.Sequential(Block(3, 64), Block(64, 64), Block(64, 128))
            self.h, self.o = nn.Linear(256, 64), nn.Linear(64, len(CLASSES))

        def forward(self, x, m):
            z = self.b(x)                                  # [n, 128, L]
            mm = m[:, None, :]
            mean = (z * mm).sum(-1) / mm.sum(-1).clamp(min=1)
            mx = z.masked_fill(mm == 0, float("-inf")).max(-1).values
            return self.o(torch.relu(self.h(torch.cat([mean, mx], 1))))
    return Net()


def _dev():
    import torch
    return torch.device("mps" if torch.backends.mps.is_available() else "cpu")


def train_one(Xtr, Ltr, ytr, wtr, Xva, Lva, yva, wva, seed, use_gap, aug_scale):
    import torch
    torch.manual_seed(seed); np.random.seed(seed)
    dev = _dev()
    xa, ma = encode(Xtr, Ltr, use_gap)
    xb, mb = encode(Xtr, Ltr, use_gap, scale=aug_scale)               # the one augmented copy per training window
    x = np.concatenate([xa, xb]); m = np.concatenate([ma, mb])
    y = np.concatenate([ytr, ytr]); w = np.concatenate([wtr, wtr]).astype(np.float32)
    xv, mv = encode(Xva, Lva, use_gap)
    T = lambda a, dt=torch.float32: torch.as_tensor(a, dtype=dt)
    x, m, y, w = T(x), T(m), T(y, torch.long), T(w)
    xv, mv, yv, wv = T(xv).to(dev), T(mv).to(dev), T(yva, torch.long).to(dev), T(wva.astype(np.float32)).to(dev)
    net = make_net().to(dev)
    opt = torch.optim.Adam(net.parameters(), lr=LR)
    best, best_state, bad, epochs = float("inf"), None, 0, 0
    g = torch.Generator().manual_seed(seed)
    for ep in range(EPOCHS):
        net.train()
        perm = torch.randperm(len(x), generator=g)
        for i in range(0, len(x), BATCH):
            j = perm[i:i + BATCH]
            loss = (torch.nn.functional.cross_entropy(net(x[j].to(dev), m[j].to(dev)), y[j].to(dev), reduction="none")
                    * w[j].to(dev)).sum() / w[j].sum().to(dev)
            opt.zero_grad(); loss.backward(); opt.step()
        net.eval()
        with torch.no_grad():
            vl = 0.0
            for i in range(0, len(xv), 2048):
                vl += float((torch.nn.functional.cross_entropy(net(xv[i:i + 2048], mv[i:i + 2048]), yv[i:i + 2048], reduction="none")
                             * wv[i:i + 2048]).sum())
            vl /= float(wv.sum())
        epochs = ep + 1
        if vl < best - 1e-4:
            best, bad = vl, 0
            best_state = {k: v.detach().cpu().clone() for k, v in net.state_dict().items()}
        else:
            bad += 1
            if bad >= PATIENCE:
                break
    net.load_state_dict(best_state)
    net.eval()
    return net.cpu(), {"epochs": epochs, "best_val_loss": round(best, 5)}


def predict(net, X, lens, use_gap):
    import torch
    x, m = encode(X, lens, use_gap)
    out = []
    with torch.no_grad():
        for i in range(0, len(x), 4096):
            out.append(torch.softmax(net(torch.as_tensor(x[i:i + 4096]), torch.as_tensor(m[i:i + 4096])), 1).numpy())
    return np.concatenate(out) if out else np.zeros((0, len(CLASSES)), np.float32)




def weights(fams, labels):
    """EXP-42's weights (copied so this file stands alone; `analyze.py check` asserts they are identical):
    every family equal total weight; within a family, every class equal."""
    fams, labels = np.asarray(fams), np.asarray(labels)
    w = np.zeros(len(labels))
    F = len(set(fams))
    for f in set(fams):
        mf = fams == f
        C = len(set(labels[mf]))
        for c in set(labels[mf]):
            m = mf & (labels == c)
            w[m] = 1.0 / (F * C * m.sum())
    return w * len(labels)
