#!/bin/bash

# Install Python dependencies
pip install -r requirements.txt

# Download the ffmpeg precompiled binary using curl
curl -L -o ffmpeg-release-64bit-static.zip https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-n4.3.1-2-gd455e4a3ca-win64-static.zip
unzip ffmpeg-release-64bit-static.zip

# List the contents of the extracted directory to verify the structure
echo "Listing contents of extracted directory:"
ls -R .

# Move the ffmpeg binaries to /usr/local/bin
mv ffmpeg-n4.3.1-2-gd455e4a3ca-win64-static/bin/ffmpeg.exe /usr/local/bin/
mv ffmpeg-n4.3.1-2-gd455e4a3ca-win64-static/bin/ffprobe.exe /usr/local/bin/

# Collect static files
python manage.py collectstatic --noinput
