from fastapi.openapi.utils import get_openapi

def patch_openapi(app):
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Force Swagger to render file upload
    openapi_schema["components"]["schemas"]["Body_analyze_statement_analyze_statement_post"] = {
        "title": "Body_analyze_statement_analyze_statement_post",
        "type": "object",
        "properties": {
            "file": {"type": "string", "format": "binary"}
        },
        "required": ["file"]
    }

    app.openapi_schema = openapi_schema
    return app.openapi_schema
