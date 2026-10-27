.PHONY: test vulnerable secure compose-up compose-down compile

test:
	python -m unittest discover -s tests -v

compile:
	python -m compileall -q app exploits tests

vulnerable:
	LAB_MODE=vulnerable PORT=5000 python -m app.main

secure:
	LAB_MODE=secure PORT=5001 python -m app.main

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down
