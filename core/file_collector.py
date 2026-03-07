from __future__ import annotations

from pathlib import Path


class FileCollector:
    IGNORED_DIRS = {".git", "node_modules", "venv", "__pycache__", "dist", "build"}
    SCANNED_EXTENSIONS = {
        ".py",
        ".js",
        ".ts",
        ".java",
        ".env",
        ".json",
        ".yaml",
        ".yml",
        ".ini",
    }

    def collect_files(self, root_path: Path) -> list[Path]:
        if not root_path.exists() or not root_path.is_dir():
            return []

        files: list[Path] = []
        for path in root_path.rglob("*"):
            if not path.is_file():
                continue
            if self._is_in_ignored_dir(path):
                continue
            if self._is_scannable(path):
                files.append(path)

        return files

    def _is_in_ignored_dir(self, path: Path) -> bool:
        return any(part in self.IGNORED_DIRS for part in path.parts)

    def _is_scannable(self, path: Path) -> bool:
        if path.name.lower() == ".env":
            return True
        return path.suffix.lower() in self.SCANNED_EXTENSIONS