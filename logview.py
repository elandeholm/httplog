import time
import base64

with open("http.log", "r") as f:
	while line := f.readline():
		minutes, haves, method, status, ct, eurl, etitle = line.rstrip().split(":")

		status = int(status)

		date = time.asctime(time.localtime(int(minutes) * 60))

		url = base64.b64decode(eurl).decode(encoding='utf-8')
		title = base64.b64decode(etitle).decode(encoding='utf-8')

		if status == 200 and title != "":
			print(f"{date}: haves={haves}, method={method}, status={status}, ct={ct}, url={url}, title={title}")
