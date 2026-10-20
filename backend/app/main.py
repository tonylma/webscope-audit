from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.history import router as history_router
from app.api.routes.reports import router as reports_router
from app.api.routes.scans import router as scans_router

app = FastAPI(title='WebScope Audit Premium', version='2.0.0', docs_url='/docs')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


@app.get('/health')
def healthcheck():
    return {'status': 'ok', 'service': 'webscope-audit', 'version': '2.0.0'}


app.include_router(scans_router)
app.include_router(reports_router)
app.include_router(history_router)
