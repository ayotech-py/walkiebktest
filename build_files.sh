#!/bin/bash

# Install Python dependencies
pip install -r requirements.txt

# Download the ffmpeg precompiled binary using curl
curl -L -o ffmpeg-release-64bit-static.zip https://github.com/GyanD/codexffmpeg/releases/download/5.0/ffmpeg-5.0-essentials_build.zip
unzip ffmpeg-release-64bit-static.zip

# List the contents of the extracted directory
echo "Listing contents of extracted directory:"
ls -R ffmpeg-5.0-essentials_build

# Navigate to the correct directory
cd ffmpeg-5.0-essentials_build/bin

# Move the ffmpeg binaries to /usr/local/bin
mv ffmpeg /usr/local/bin/
mv ffprobe /usr/local/bin/

# Return to project root directory
cd ../..

# Collect static files
python manage.py collectstatic --noinput
