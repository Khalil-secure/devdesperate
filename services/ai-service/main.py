from fastapi import FastAPI

app = FastAPI(title="DevDesperate AI Service")

@app.get("/health")
def health():
    return {"status": "ok", "service": "ai-service"}
