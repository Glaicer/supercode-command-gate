#!/bin/sh
set -eu

version="${AAR_RELEASE_VERSION:-${1:-}}"
if [ -z "$version" ]; then
  echo "usage: AAR_RELEASE_VERSION=0.1.0 npm run release:reviewer" >&2
  exit 2
fi

case "$version" in
  v*) version="${version#v}" ;;
esac

output_dir="${AAR_RELEASE_DIR:-dist/reviewer-v${version}}"
mkdir -p "$output_dir"

for target in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64 windows-arm64; do
  case "$target" in
    linux-amd64) os=linux; arch=amd64 ;;
    linux-arm64) os=linux; arch=arm64 ;;
    darwin-amd64) os=darwin; arch=amd64 ;;
    darwin-arm64) os=darwin; arch=arm64 ;;
    windows-amd64) os=windows; arch=amd64 ;;
    windows-arm64) os=windows; arch=arm64 ;;
    *) echo "unsupported release target: $target" >&2; exit 2 ;;
  esac

  binary="$output_dir/aar-v${version}-${os}-${arch}"
  if [ "$os" = windows ]; then
    binary="${binary}.exe"
  fi
  if [ -e "$binary" ]; then
    echo "refusing to overwrite existing release artifact: $binary" >&2
    exit 1
  fi
  echo "building $binary"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build \
    -trimpath \
    -ldflags "-s -w -X main.version=v${version}" \
    -o "$binary" ./cmd/aar
done

checksum_file="$output_dir/SHA256SUMS"
if [ -e "$checksum_file" ]; then
  echo "refusing to overwrite existing checksum file: $checksum_file" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$output_dir" && sha256sum aar-v*) > "$checksum_file"
else
  (cd "$output_dir" && shasum -a 256 aar-v*) > "$checksum_file"
fi

echo "reviewer release written to $output_dir"
