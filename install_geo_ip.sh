#!/usr/bin/env bash


echo "------------------------------------"
echo "           install GeoIP            "
echo "------------------------------------"

#pip3 install libgeoip-dev
#sudo pip3 install geoip2
cd common_analysis_ip_and_uri_finder/
mkdir bin
cd bin/
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz
mkdir GeoLite2-City && tar xf GeoLite2-City.tar.gz -C GeoLite2-City --strip-components 1
rm GeoLite2-City.tar.gz
