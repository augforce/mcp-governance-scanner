"""FastAPI front end: / /scan /history /scan/{id}.

The home page is deliberately one thing: a native folder picker and a Scan
button. Picking a folder uploads its files; the scanner decides whether the
folder is an MCP server and either scans it or reports that none was found.
Run: python -m app.main (http://127.0.0.1:8901).
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from analysis.claude_judge import narrative
from analysis.explainer import explain
from app import db
from app.scan import scan_artifact
from providers.folder import detect_mcp_server
from scanning.provenance import maybe_fetch_provenance

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "scans.db"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def create_app(db_path: Path | str | None = None) -> FastAPI:
    app = FastAPI(title="MCP Server Security & Governance Scanner")
    app.state.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
    templates = Jinja2Templates(directory=TEMPLATES_DIR)

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        return templates.TemplateResponse(request, "index.html")

    @app.post("/scan", response_class=HTMLResponse)
    def scan(request: Request, files: list[UploadFile]):
        tree = {f.filename: f.file.read() for f in files if f.filename}
        artifact = detect_mcp_server(tree)
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
            source="folder",
            result=result,
            report=report,
            narrative=narrative(result, server_name=name),  # None unless API key set
        )
        return RedirectResponse(f"/scan/{scan_id}", status_code=303)

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
