#!/bin/bash

# Install Python dependencies
pip install -r requirements.txt

# Install FFmpeg using ffmpeg-downloader
python - <<END
import os
from ffmpeg_downloader import ffdl

# Install FFmpeg
ffdl.install(overwrite=True)

# Get the installed path of ffmpeg
ffmpeg_path = ffdl.ffmpeg_path()
ffprobe_path = ffdl.ffprobe_path()

# Print paths to use them in the script
print(f"FFMPEG_PATH={ffmpeg_path}")
print(f"FFPROBE_PATH={ffprobe_path}")
END

# Capture the output of the Python script to set environment variables
FFMPEG_PATH=$(python -c 'from ffmpeg_downloader import ffdl; print(ffdl.ffmpeg_path())')
FFPROBE_PATH=$(python -c 'from ffmpeg_downloader import ffdl; print(ffdl.ffprobe_path())')

# Verify the installation
$FFMPEG_PATH -version
$FFPROBE_PATH -version
