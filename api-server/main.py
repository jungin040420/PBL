from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def read_root():
    return {"status": "api-server 실행중"}