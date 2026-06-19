rm -rf /opt/jxwaf_admin_server/lualib/resty/admin_server/
cp -r admin_server/ /opt/jxwaf_admin_server/lualib/resty/
/opt/jxwaf_admin_server/nginx/sbin/nginx -s reload