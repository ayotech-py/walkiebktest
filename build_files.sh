#!/bin/bash

# Install Python dependencies
pip install -r requirements.txt

# Install FFmpeg using ffmpeg-downloader
python -c "from ffmpeg_downloader import ffdl; ffdl.install(overwrite=True)"

# Verify the installation
ffmpeg -version
ffprobe -version
