# Building

cd nginx-* && ./configure --add-dynamic-module=../module && make -j16 build modules && cd ..

# Test

./nginx-*/objs/nginx -c nginx.conf -p ngx-run