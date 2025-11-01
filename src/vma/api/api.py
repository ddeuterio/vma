from loguru import logger
from fastapi import FastAPI

import vma.helper as helper
import vma.api.routers.v1 as v1

api_server = FastAPI()
helper.configure_logging('DEBUG', uvicorn=True)
api_server.include_router(router=v1.router)