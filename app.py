from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class ChargeRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: float
    days_in_actual_month: float
    spec: str


@app.post("/charge")
def charge(req: ChargeRequest):

    difference = req.new_price - req.old_price

    if req.spec == "v1":
        charge = difference * req.days_remaining / 30

    elif req.spec == "v2":
        charge = difference * req.days_remaining / req.days_in_actual_month

    else:
        return {"error": "Invalid spec"}

    return {"charge": charge}