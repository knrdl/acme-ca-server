from fastapi import FastAPI

def test_acme_order(fastapi_app: FastAPI):
    print(fastapi_app)