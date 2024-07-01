#!/bin/bash

# Download the ffmpeg static build
wget https://johnvansickle.com/ffmpeg/releases/ffmpeg-release-64bit-static.tar.xz
tar -xvf ffmpeg-release-64bit-static.tar.xz
cd ffmpeg-*-static

# Move the ffmpeg binaries to /usr/local/bin
mv ffmpeg /usr/local/bin/
mv ffprobe /usr/local/bin/
