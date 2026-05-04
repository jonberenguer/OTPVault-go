BINARY  := otpvault
DIST    := dist
IMAGE   := otpvault-build

.PHONY: build-linux build-windows build-all test clean

build-linux:
	mkdir -p $(DIST)
	docker build --target export-linux --output type=local,dest=$(DIST) .
	mv $(DIST)/$(BINARY) $(DIST)/$(BINARY)-linux-amd64

build-windows:
	mkdir -p $(DIST)
	docker build --target export-windows --output type=local,dest=$(DIST) .
	mv $(DIST)/$(BINARY).exe $(DIST)/$(BINARY)-windows-amd64.exe

build-all: build-linux build-windows

test:
	docker build --target test --tag $(IMAGE)-test .

clean:
	rm -rf $(DIST)
	docker rmi -f $(IMAGE)-test 2>/dev/null || true
