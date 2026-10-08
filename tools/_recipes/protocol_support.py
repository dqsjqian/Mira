"""Mira-specific attribution and MSVC debug-symbol installation hooks."""

import re
import shutil
from pathlib import Path

DEPENDENCIES = (("nghttp2",), ("nghttp3",), ("ngtcp2",))

def install_compile_pdbs(build: Path, prefix: Path) -> None:
    # The pinned projects give each MSVC compiler PDB the static target's name,
    # but their install rules only copy the archive. Preserve those PDBs beside
    # the installed .lib before the temporary build tree is removed, so LINK
    # retains dependency debug information instead of reporting LNK4099.
    # Release and MinGW archives do not necessarily have compiler PDBs.
    library_dir = prefix / "lib"
    copies = []
    for archive in sorted(library_dir.glob("*_static.lib")):
        filename = archive.with_suffix(".pdb").name
        matches = sorted(build.rglob(filename))
        if len(matches) > 1:
            raise ValueError(f"Ambiguous compiler PDB for {archive.name}: {matches}")
        if matches:
            copies.append((matches[0], library_dir / filename))
    for source, destination in copies:
        shutil.copyfile(source, destination)
        print(f"Installed compiler debug symbols: {destination}", flush=True)


def install_dependency_licenses(source: Path, prefix: Path, name: str) -> None:
    """Keep upstream terms and embedded notices beside the built libraries."""
    if name not in {dependency[0] for dependency in DEPENDENCIES}:
        raise ValueError(f"Unknown protocol dependency: {name}")
    # These pinned projects compile their runtime implementation from lib/.
    # ngtcp2 additionally builds only the ossl adapter and shared crypto code;
    # tests, examples and disabled TLS adapters are not part of these libraries.
    roots = [source / "lib"]
    if name == "ngtcp2":
        roots += [source / relative for relative in (
            "crypto/shared.c", "crypto/shared.h", "crypto/ossl",
            "crypto/includes/ngtcp2/ngtcp2_crypto.h",
            "crypto/includes/ngtcp2/ngtcp2_crypto_ossl.h",
        )]
    files = {source / "COPYING"}
    for root in roots:
        if root.is_dir():
            files.update(path for path in root.rglob("*") if path.is_file())
        elif root.is_file():
            files.add(root)
    license_dir = prefix / "share/licenses" / name
    license_dir.mkdir(parents=True, exist_ok=True)
    notices: dict[str, list[str]] = {}
    for path in sorted(files):
        relative = path.relative_to(source)
        if path.name.split(".", 1)[0].upper() in ("COPYING", "LICENSE", "NOTICE"):
            destination = license_dir / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
        elif path.name.endswith((".c", ".h", ".h.in")):
            # Keep the entire original comment block, including notices that
            # occur after implementation code (sfparse's UTF-8 DFA does this).
            for block in re.findall(r"/\*.*?\*/", path.read_text(encoding="utf-8"), re.DOTALL):
                if "copyright" in block.lower():
                    notices.setdefault(block, []).append(relative.as_posix())
    if not notices:
        raise ValueError(f"No runtime copyright notices found in {source}")
    text = [f"Upstream runtime source notices for {name}.\n"
            "Original comment blocks are retained without changing their terms.\n"]
    for block, paths in notices.items():
        text.append("\nSource: " + ", ".join(paths) + "\n" + block + "\n")
    (license_dir / "SOURCE-NOTICES.txt").write_text("".join(text), encoding="utf-8")
    if name == "ngtcp2":
        # These embedded sources refer to external license files absent from
        # ngtcp2's archive. Keep immutable upstream copies in this repository;
        # this build step never fetches license text from the network.
        extra_licenses = Path(__file__).resolve().parents[1] / "ci/licenses"
        for filename in ("quiche-LICENSE", "pcg-LICENSE-MIT.txt", "SOURCES.md"):
            shutil.copyfile(extra_licenses / filename, license_dir / filename)
