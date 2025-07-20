import azure.functions as func
import logging

app = func.FunctionApp()


@app.function_name(name="MyHttpFunction")
@app.route(route="hello", auth_level=func.AuthLevel.ANONYMOUS)
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing HTTP request.")
    name = req.params.get("name")

    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            req_body = {}
        name = req_body.get("name")

    if name:
        return func.HttpResponse(f"Hello, {name}!")
    else:
        return func.HttpResponse(
            "Please pass a name on the query string or in the request body.",
            status_code=400,
        )
