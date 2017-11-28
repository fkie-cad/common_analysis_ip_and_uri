#!/usr/bin/env bash


echo "------------------------------------"
echo "           install GeoIP            "
echo "------------------------------------"

#pip3 install libgeoip-dev
sudo pip3 install geoip2
mkdir bin
cd bin/
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz
tar -xvzf GeoLite2-City.tar.gz
rm GeoLite2-City.tar.gz