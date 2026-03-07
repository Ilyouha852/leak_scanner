from __future__ import annotations

from pathlib import Path


class ProjectDetector:

    MARKER_FILES = {
        "package.json",
        "requirements.txt",
        "Dockerfile",
        "pom.xml",
        "Makefile",
    }
    SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".java", ".cpp"}

    def is_project(self, folder_path: Path) -> bool:
        if not folder_path.exists() or not folder_path.is_dir():
            return False

        if any((folder_path / marker).exists() for marker in self.MARKER_FILES):
            return True

        source_count = 0
        for path in folder_path.rglob("*"):
            if path.is_file() and path.suffix.lower() in self.SOURCE_EXTENSIONS:
                source_count += 1
                if source_count > 3:
                    return True

        return False