#!/bin/bash

# Install Python dependencies
pip install -r requirements.txt

# Define FFmpeg version and URL
FFMPEG_VERSION="4.3.2"
OS_TYPE="linux-64"
FFMPEG_URL="https://johnvansickle.com/ffmpeg/releases/ffmpeg-release-${OS_TYPE}-static.tar.xz"

# Create a directory for FFmpeg binaries
mkdir -p ffmpeg
cd ffmpeg

# Download and extract FFmpeg using curl and unxz
curl -L $FFMPEG_URL -o ffmpeg.tar.xz
# Install xz-utils to handle .xz files
apk add xz
unxz ffmpeg.tar.xz
tar -xvf ffmpeg.tar --strip-components=1

# Make FFmpeg and FFprobe available in the PATH
export PATH=$PATH:$(pwd)

# Verify the installation
./ffmpeg -version
./ffprobe -version
