#!/bin/bash

# Install Python dependencies
pip install -r requirements.txt

# Download the ffmpeg static build using curl
curl -L -o ffmpeg-release-64bit-static.tar.xz https://johnvansickle.com/ffmpeg/releases/ffmpeg-release-64bit-static.tar.xz
tar -xvf ffmpeg-release-64bit-static.tar.xz
cd ffmpeg-*-static

# Move the ffmpeg binaries to /usr/local/bin
mv ffmpeg /usr/local/bin/
mv ffprobe /usr/local/bin/

# Return to project root directory
cd ..