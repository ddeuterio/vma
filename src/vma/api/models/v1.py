from typing import Any
from pydantic import BaseModel

class Product(BaseModel):
    name: str
    description: str | None = None

class Image(BaseModel):
    name: str
    version: str
    product: str

class Import(BaseModel):
    scanner: str
    product: str
    image: str
    version: str
    data: Any