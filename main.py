from fastapi import FastAPI, Query, Body, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import random
import string

app = FastAPI(title="Password Generator API", version="1.0")

SYMBOLS = "!@#$%&*"


def generate_password(
    length: int, use_upper: bool, use_lower: bool, use_digits: bool, use_symbols: bool
) -> str:
    character_pool = ""
    if use_upper:
        character_pool += string.ascii_uppercase
    if use_lower:
        character_pool += string.ascii_lowercase
    if use_digits:
        character_pool += string.digits
    if use_symbols:
        character_pool += SYMBOLS

    if not character_pool:
        raise HTTPException(
            status_code=400, detail="At least one character type must be enabled."
        )

    return "".join(random.choice(character_pool) for _ in range(length))


@app.get("/generate")
def generate(
    length: int = Query(12, ge=4),
    uppercase: bool = Query(True),
    lowercase: bool = Query(True),
    digits: bool = Query(True),
    symbols: bool = Query(True),
):
    password = generate_password(length, uppercase, lowercase, digits, symbols)
    return {"password": password}


@app.get("/strength")
def check_strength(password: str = Query(..., min_length=1)):
    score = 0
    recommendation = []

    if len(password) < 6:
        strength = "Very Weak"
        recommendation.append("Use at least 6 characters.")
    else:
        if any(c.islower() for c in password):
            score += 1
        else:
            recommendation.append("Add lowercase letters.")

        if any(c.isupper() for c in password):
            score += 1
        else:
            recommendation.append("Add uppercase letters.")

        if any(c.isdigit() for c in password):
            score += 1
        else:
            recommendation.append("Add digits.")

        if any(c in SYMBOLS for c in password):
            score += 1
        else:
            recommendation.append("Add symbols such as !@#$%&*.")

        if score == 1:
            strength = "Weak"
        elif score == 2:
            strength = "Moderate"
        elif score == 3:
            strength = "Strong"
        elif score == 4:
            strength = "Very Strong"
        else:
            strength = "Very Weak"

    return {
        "password": password,
        "score": score,
        "strength": strength,
        "recommendation": " ".join(recommendation)
        if recommendation
        else "Good password.",
    }


class BatchRequest(BaseModel):
    length: int
    count: int
    uppercase: Optional[bool] = True
    lowercase: Optional[bool] = True
    digits: Optional[bool] = True
    symbols: Optional[bool] = True


@app.post("/generate/batch")
def generate_batch(request: BatchRequest):
    if request.length < 4:
        raise HTTPException(status_code=400, detail="Minimum length is 4.")
    if request.count > 100:
        raise HTTPException(
            status_code=400, detail="Maximum number of passwords is 100."
        )
    if not (
        request.uppercase or request.lowercase or request.digits or request.symbols
    ):
        raise HTTPException(
            status_code=400, detail="At least one character type must be enabled."
        )

    passwords = [
        generate_password(
            request.length,
            request.uppercase,
            request.lowercase,
            request.digits,
            request.symbols,
        )
        for _ in range(request.count)
    ]
    return {"passwords": passwords}


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
