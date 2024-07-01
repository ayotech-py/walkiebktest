#!/bin/bash

# Install Python dependencies
mv ffmpeg /var/task/ffmpeg
mv ffprobe /var/task/ffprobe

ls -l /usr/local/bin/ffmpeg
ls -l /usr/local/bin/

ls /var/task

# Verify that ffmpeg and ffprobe are installed correctly

pip install -r requirements.txt




