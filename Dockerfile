FROM golang:1.21-bookworm AS builder

# Fyne requires CGO and these system libs for the GUI toolkit
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    gcc-mingw-w64-x86-64 \
    libgl1-mesa-dev \
    libx11-dev \
    libxrandr-dev \
    libxinerama-dev \
    libxcursor-dev \
    libxi-dev \
    libxxf86vm-dev \
    pkg-config \
    librsvg2-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy everything so go mod tidy can resolve imports from source
COPY go.mod *.go *.svg ./
# Convert SVG icon to PNG before go build (required by //go:embed in icon.go)
RUN rsvg-convert -w 256 -h 256 Icon.svg -o Icon.png
# Generate go.sum and cache dependencies before the full build
RUN go mod tidy
RUN go mod download

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o otpvault .
RUN CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
    go build -ldflags "-H windowsgui" -o otpvault.exe .

# ── Test stage ────────────────────────────────────────────────────────────────
FROM builder AS test
RUN go test ./... -v

# ── Export stage (Linux) — used by `make build-linux`
FROM scratch AS export-linux
COPY --from=builder /build/otpvault /otpvault

# ── Export stage (Windows) — used by `make build-windows`
FROM scratch AS export-windows
COPY --from=builder /build/otpvault.exe /otpvault.exe

# ── Runtime stage ─────────────────────────────────────────────────────────────
# Minimal image with X11/GL runtime libs so the binary can run on a host
# with a display forwarded (e.g. DISPLAY=:0 via X11 socket mount).
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1-mesa-glx \
    libx11-6 \
    libxrandr2 \
    libxinerama1 \
    libxcursor1 \
    libxi6 \
    libxxf86vm1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/otpvault .

# otp-accounts.json is written next to the binary; mount a volume to persist it.
VOLUME ["/app"]

ENTRYPOINT ["./otpvault"]
