"""FastAPI front end: / /scan /upload /history /scan/{id}.

Thin layer over the deterministic engine — every scan goes through
app.scan.scan_artifact / scan_directory; the web layer only ingests,
stores, and renders. Run: python -m app.main (http://127.0.0.1:8901).
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from analysis.claude_judge import narrative
from analysis.explainer import explain
from app import db
from app.scan import scan_artifact
from providers.local_dir import IngestError
from providers.upload import IngestError as UploadIngestError
from providers.upload import ingest_upload

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "scans.db"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def create_app(db_path: Path | str | None = None) -> FastAPI:
    app = FastAPI(title="MCP Server Security & Governance Scanner")
    app.state.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
    templates = Jinja2Templates(directory=TEMPLATES_DIR)

    def store_and_redirect(name: str, source: str, result) -> RedirectResponse:
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
        return templates.TemplateResponse(request, "index.html")

    @app.post("/scan", response_class=HTMLResponse)
    def scan_local(
        request: Request, path: str = Form(...), manifest_path: str = Form("")
    ):
        from providers.local_dir import ingest
        from scanning.provenance import maybe_fetch_provenance

        try:
            artifact = ingest(path, manifest_path=manifest_path or None)
        except IngestError as exc:
            return PlainTextResponse(str(exc), status_code=400)
        result = scan_artifact(
            artifact, provenance_report=maybe_fetch_provenance(artifact.manifest)
        )
        name = artifact.manifest.get("name") or Path(path).name or "server"
        return store_and_redirect(name, source=f"local: {path}", result=result)

    @app.post("/upload", response_class=HTMLResponse)
    def scan_upload(request: Request, files: list[UploadFile]):
        try:
            artifact = ingest_upload(
                {f.filename: f.file.read() for f in files if f.filename}
            )
        except UploadIngestError as exc:
            return PlainTextResponse(str(exc), status_code=400)
        result = scan_artifact(artifact)
        name = artifact.manifest.get("name", "uploaded-server")
        return store_and_redirect(name, source="upload", result=result)

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
