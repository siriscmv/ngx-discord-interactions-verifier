# Installing

## Prebuilt binary
- Download the appropriate `.so` file (the version number should match the version of nginx installed on your system) from the `build` directory
- Copy the `.so` file to the nginx modules directory (typically `/etc/nginx/modules-enabled`)
- Add the following line to the top of your `nginx.conf` file:
```
    load_module modules-enabled/interactions-verifier-1_18_0.so;
```

## Building from source
- Clone this repository
- Download nginx from the [nginx website](https://nginx.org/download/) & extract it
- Switch to the new directory and run `./configure --add-dynamic-module=../module && make -j16 build modules`
- The `ngx_discord_interactions_verifier.so` file will be located at the `nginx-x.x.x/objs/` directory
- Follow the remaining steps from the "Prebuilt binary" section


# Usage
- After using the `load_module` directive, you can use the `verify_interactions` directive in your `server` or `location` block to verify interactions from Discord
- Example:
```
http {
  server {
    listen 80;

    location /interactions {
      verify_interactions <Your public key here>;
      proxy_pass http://localhost:xxxx;
    }
  }
}
```

# Credits
- ed25519 implementation by [orlp](https://github.com/orlp/ed25519)
