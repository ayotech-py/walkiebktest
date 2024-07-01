#!/bin/bash

# Install Python dependencies
pip install -r requirements.txt

# Download the ffmpeg precompiled binary using curl
curl -L -o ffmpeg.tar.xz https://johnvansickle.com/ffmpeg/releases/ffmpeg-release-i686-static.tar.xz
tar -xf ffmpeg.tar.xz
cd ffmpeg-*-static

# Move the ffmpeg binaries to /usr/local/bin
mv ffmpeg /usr/local/bin/
mv ffprobe /usr/local/bin/

# Return to project root directory
cd ..