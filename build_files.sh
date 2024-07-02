#!/bin/bash

# Install Python dependencies
pip install -r requirements.txt

# Install FFmpeg using ffmpeg-downloader
python -m ffmpeg_downloader install --add-path

# Verify the installation
ffmpeg -version
ffprobe -version
