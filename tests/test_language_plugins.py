"""Every language plugin must reproduce clients/test_vectors.json."""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def run(cmd, timeout=180):
    proc = subprocess.run(
        cmd, cwd=ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout)
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr


def test_python_plugin():
    run([sys.executable, str(ROOT / "plugins" / "python" / "oxmp_plugin.py")])


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_javascript_plugin():
    proc = subprocess.run(
        ["node", "--test", str(ROOT / "plugins" / "javascript" / "conformance.test.mjs")],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.skipif(shutil.which("javac") is None, reason="javac not installed")
def test_java_plugin(tmp_path):
    src = ROOT / "plugins" / "java" / "src" / "oxmp"
    out = tmp_path / "classes"
    out.mkdir()
    compile_cmd = ["javac", "-encoding", "UTF-8", "-d", str(out),
                   str(src / "OxmpPlugin.java"), str(src / "Conformance.java")]
    compiled = subprocess.run(compile_cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    # javac may be a newer JDK than the `java` that appears first on PATH.
    java = str(Path(shutil.which("javac")).with_name("java.exe"))
    run([java, "-cp", str(out), "oxmp.Conformance"])


@pytest.mark.skipif(shutil.which("dotnet") is None, reason="dotnet not installed")
def test_csharp_plugin():
    run(["dotnet", "run", "--project", str(ROOT / "plugins" / "csharp"),
         "-c", "Release", "--nologo"], timeout=240)


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo not installed")
def test_rust_plugin():
    run(["cargo", "test", "--quiet", "--manifest-path",
         str(ROOT / "plugins" / "rust" / "Cargo.toml")], timeout=240)


@pytest.mark.skipif(shutil.which("php") is None, reason="php not installed")
def test_php_plugin():
    modules = subprocess.run(
        ["php", "-m"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    cmd = ["php"]
    if "sodium" not in modules.stdout.lower():
        cmd += ["-d", "extension=sodium"]
    cmd.append(str(ROOT / "plugins" / "php" / "conformance.php"))
    run(cmd)
