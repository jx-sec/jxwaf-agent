rm -rf /opt/jxwaf/lualib/resty/jxwaf/
cp -r jxwaf/ /opt/jxwaf/lualib/resty/
/opt/jxwaf/nginx/sbin/nginx -s reload