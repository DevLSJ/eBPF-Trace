"""모사 이미지 서비스 — 런타임 축(docs/13 §8) 공격 시연용 백엔드.

중고거래 앱의 "사진 올리기"를 받아 썸네일을 만들어 저장한다. 외부 전송은 없다.
"""

import io
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import redis
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from img_optimize_demo import optimize  # 오염된 데모 의존성 (docs/13 §8)
from PIL import Image, UnidentifiedImageError

MAX_BYTES = 5 * 1024 * 1024
THUMB_SIZE = (320, 320)
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", "/data/uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

r = redis.Redis.from_url(os.environ["REDIS_URL"], socket_timeout=2)
app = FastAPI(title="carrot-image-service", docs_url=None, redoc_url=None)


def log(level: str, msg: str, **extra) -> None:
    print(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "level": level,
                      "svc": "carrot-image", "msg": msg, **extra}), flush=True)


@app.get("/health")
def health() -> JSONResponse:
    try:
        ok = bool(r.ping())
    except redis.RedisError:
        ok = False
    return JSONResponse({"ok": ok, "svc": "carrot-image", "redis": ok}, status_code=200 if ok else 503)


@app.post("/upload", status_code=201)
async def upload(file: UploadFile = File(...)) -> dict:
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(413, "file too large (max 5MB)")
    try:
        img = Image.open(io.BytesIO(data))
        img.verify()
        img = Image.open(io.BytesIO(data)).convert("RGB")
    except (UnidentifiedImageError, OSError):
        raise HTTPException(400, "not a valid image")
    width, height = img.size
    img.thumbnail(THUMB_SIZE)
    image_id = uuid.uuid4().hex
    img.save(UPLOAD_DIR / f"{image_id}.jpg", "JPEG", quality=80)
    optimize("upload")  # 이미지 최적화 — 오염 버전은 여기서 fake-c2로 비콘을 보낸다
    r.incr("image:uploads:count")
    log("info", "image uploaded", image_id=image_id, bytes=len(data), width=width, height=height)
    return {"imageId": image_id, "width": width, "height": height, "bytes": len(data)}
