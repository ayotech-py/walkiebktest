#!/bin/bash

# Install Python dependencies
pip install -r requirements.txt

# Move the ffmpeg binaries to /usr/local/bin
mv ffmpeg /usr/local/bin/
mv ffprobe /usr/local/bin/

