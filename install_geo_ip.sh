#!/usr/bin/env bash

# 'sudo pip3 install geoip2' need to be executed before this module installation

echo "------------------------------------"
echo "           install GeoIP            "
echo "------------------------------------"

cd common_analysis_ip_and_uri_finder/
if [ -e bin/ ]
then
    sudo rm -R bin/
    echo "---------------------------------------------"
    echo " Updating Geolocation GeoLite2-city Database "
    echo "---------------------------------------------"
fi
mkdir bin
cd bin/
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz
mkdir GeoLite2-City && tar xf GeoLite2-City.tar.gz -C GeoLite2-City --strip-components 1
rm GeoLite2-City.tar.gz
