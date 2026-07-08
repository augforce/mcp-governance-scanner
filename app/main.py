"""FastAPI front end: / /scan /scan-path /history /scan/{id}.

The home page is a native folder picker plus a local-path fallback. Picking a
folder uploads its files — the page filters out dependency/system bulk
(.venv, node_modules, …) in the browser first, so real project roots fit in
one upload. The path fallback reads the folder server-side through the same
pipeline, with no upload and no size limit. Either way the scanner decides
whether the folder is an MCP server and scans it or reports that none was
found. Run: python -m app.main (http://127.0.0.1:8901).
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.formparsers import MultiPartException

from analysis.claude_judge import narrative
from analysis.explainer import explain
from app import db
from app.scan import scan_artifact
from providers.folder import detect_mcp_server
from providers.local_dir import (
    DOC_EXTENSIONS,
    MAX_FILE_BYTES,
    SKIP_DIRS,
    SOURCE_EXTENSIONS,
    SPECIAL_SOURCE_NAMES,
    read_tree,
)
from scanning.provenance import maybe_fetch_provenance

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "scans.db"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

# Multipart file-count cap for folder uploads. Starlette's default
# (max_files=1000) rejects real project folders outright; the browser-side
# filter removes dependency/system bulk and this raised cap absorbs the rest.
# (Per-file size is not limited by the parser — file parts spool to disk —
# so only the count matters.) The path-entry fallback exists for anything
# larger still.
UPLOAD_MAX_FILES = 20_000
UPLOAD_TOO_LARGE_MESSAGE = (
    "That folder has too many files to upload even after excluding "
    "dependency folders. Use the local path option instead — it reads the "
    "folder directly on this machine, so there is no size limit."
)


def create_app(db_path: Path | str | None = None) -> FastAPI:
    app = FastAPI(title="MCP Server Security & Governance Scanner")
    app.state.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
    templates = Jinja2Templates(directory=TEMPLATES_DIR)

    def render_index(request: Request, error: str | None = None):
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "error": error,
                "skip_dirs": sorted(SKIP_DIRS),
                "keep_extensions": sorted(SOURCE_EXTENSIONS | DOC_EXTENSIONS),
                "keep_names": sorted(SPECIAL_SOURCE_NAMES),
                "max_file_bytes": MAX_FILE_BYTES,
            },
        )

    def finish_scan(request: Request, artifact, source: str):
        if artifact is None:
            return templates.TemplateResponse(request, "not_found.html")
        result = scan_artifact(
            artifact, provenance_report=maybe_fetch_provenance(artifact.manifest)
        )
        name = artifact.manifest.get("name") or "server"
        report = explain(result)
        scan_id = db.save_scan(
            app.state.db_path,
            name=name,
            source=source,
            result=result,
            report=report,
            narrative=narrative(result, server_name=name),  # None unless API key set
        )
        return RedirectResponse(f"/scan/{scan_id}", status_code=303)

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        return render_index(request)

    @app.post("/scan", response_class=HTMLResponse)
    async def scan(request: Request):
        try:
            form = await request.form(max_files=UPLOAD_MAX_FILES)
        # Starlette raises MultiPartException in debug mode but converts it
        # to a 400 HTTPException otherwise — treat both as "over the cap".
        except (MultiPartException, StarletteHTTPException):
            return render_index(request, error=UPLOAD_TOO_LARGE_MESSAGE)
        tree = {
            item.filename: await item.read()
            for item in form.getlist("files")
            if isinstance(item, UploadFile) and item.filename
        }
        return finish_scan(request, detect_mcp_server(tree), source="folder")

    @app.post("/scan-path", response_class=HTMLResponse)
    def scan_path(request: Request, local_path: str = Form("")):
        root = Path(local_path.strip()).expanduser()
        if not local_path.strip() or not root.is_dir():
            return render_index(
                request,
                error=f"Not a folder on this machine: {local_path.strip() or '(empty)'}",
            )
        return finish_scan(request, detect_mcp_server(read_tree(root)), source="path")

    @app.get("/history", response_class=HTMLResponse)
    def history(request: Request):
        return templates.TemplateResponse(
            request, "history.html", {"scans": db.list_scans(app.state.db_path)}
        )

    @app.get("/scan/{scan_id}", response_class=HTMLResponse)
    def scan_detail(request: Request, scan_id: int):
        scan = db.get_scan(app.state.db_path, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        return templates.TemplateResponse(request, "result.html", {"scan": scan})

    return app


app = create_app(os.environ.get("MCP_SCANNER_DB"))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8901)
