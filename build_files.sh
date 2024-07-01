#!/bin/bash

# Install Python dependencies
pip install -r requirements.txt

# Download the ffmpeg precompiled binary using curl
curl -L -o ffmpeg-release-64bit-static.zip https://github.com/GyanD/codexffmpeg/releases/download/5.0/ffmpeg-5.0-essentials_build.zip
unzip ffmpeg-release-64bit-static.zip
cd ffmpeg-5.0-essentials_build/bin

# Move the ffmpeg binaries to /usr/local/bin
mv ffmpeg /usr/local/bin/
mv ffprobe /usr/local/bin/

# Return to project root directory
cd ../..

# Collect static files
python manage.py collectstatic --noinput
