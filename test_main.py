import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_generate_password_default():
    response = client.get("/generate")
    assert response.status_code == 200
    password = response.json()["password"]
    assert isinstance(password, str)
    assert len(password) == 12


def test_generate_password_custom_length():
    response = client.get(
        "/generate?length=16&uppercase=true&lowercase=true&digits=true&symbols=true"
    )
    assert response.status_code == 200
    assert len(response.json()["password"]) == 16


def test_generate_password_invalid_options():
    response = client.get(
        "/generate?uppercase=false&lowercase=false&digits=false&symbols=false"
    )
    assert response.status_code == 400


def test_check_strength_very_weak():
    response = client.get("/strength?password=abc")
    assert response.status_code == 200
    result = response.json()
    assert result["strength"] in ["Very Weak", "Weak"]
    assert result["score"] <= 1


def test_check_strength_strong_password():
    response = client.get("/strength?password=Abc123$%")
    assert response.status_code == 200
    result = response.json()
    assert result["score"] >= 3
    assert result["strength"] in ["Strong", "Very Strong"]


def test_generate_batch_success():
    request_body = {
        "length": 10,
        "count": 5,
        "uppercase": True,
        "lowercase": True,
        "digits": True,
        "symbols": False,
    }
    response = client.post("/generate/batch", json=request_body)
    assert response.status_code == 200
    passwords = response.json()["passwords"]
    assert len(passwords) == 5
    for pwd in passwords:
        assert isinstance(pwd, str)
        assert len(pwd) == 10


def test_generate_batch_invalid_length():
    request_body = {"length": 2, "count": 3, "uppercase": True, "lowercase": True}
    response = client.post("/generate/batch", json=request_body)
    assert response.status_code == 400


def test_generate_batch_invalid_count():
    request_body = {"length": 8, "count": 200, "uppercase": True}
    response = client.post("/generate/batch", json=request_body)
    assert response.status_code == 400
