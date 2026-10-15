"""EXP-52: PyTorch is a training-only dependency. The shipped package must run without it (NumPy inference only)."""
import pathlib
import re

import tunnelscope

PKG = pathlib.Path(tunnelscope.__file__).parent


def test_the_package_never_imports_torch():
    hits = [str(p.relative_to(PKG)) for p in PKG.rglob("*.py")
            if re.search(r"^\s*(import|from)\s+torch\b", p.read_text(), re.M) or "__import__(\"torch\")" in p.read_text()]
    assert not hits, f"torch imported inside the tunnelscope package: {hits}"


def test_torch_is_only_an_optional_training_extra():
    text = (PKG.parent / "pyproject.toml").read_text()
    deps = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, re.M | re.S).group(1)
    assert "torch" not in deps
    assert re.search(r'^train\s*=\s*\["torch', text, re.M)
