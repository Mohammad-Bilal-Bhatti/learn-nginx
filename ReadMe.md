# Nginx Fundamentals

Course Metadata
- Course started date: 22-May-2022 
- Course ended date: 04-Jun-2022
- Instructor: Ray Viljoen
- Source: Udemy-Free


About Nginx
- created in 2004
- nginx is the web server developed by Igor Sysoev, CTO and Co-Founder, NGINX Inc.
- fustrated with apache that should capable enough of handling 10k requests 
- nginx aims
  - high performance
  - high concurrency (handle multiple requests at single time)
  - low resource usage
- has its large first and third party modules to extend its functionality
- at its core nginx is designed as a reverse proxy web server 


## Nginx vs Apache


Apache
- by default apache is configured as prefork mode (it means it has set number of processes which handles one request at one time either img, or php script)
- apache can handle upto defined number of requests configured at apache
- apache configuration uses defaults and highly favours to file system location first
- .htaccess is used to bind directories with routes - that causes performance panelty

```xml
<Directory "/www/site/images">
</Directory>
```

Nginx
- nginx single process can handle multiple requests concurrently/asynchronously
- because of its asynchronous design unlike apache - nginx can't embed server side programming language into its own processes.
- this design makes apache less resource hungry, by overlifting to elsewhere
- nginx could be configured for serving both static and dynamic content (mixed content)
- Apache is faster then Apache
  - Serve static resources faster
  - Higher Concurrency
- Nginx configuration uses uri location first.
- This configuration make easy for nginx to not only serve as a web-server but like load-balancer or mail-server as well
```conf
location /images {
  ...
}
```

## Installing Nginx

- for using nginx we need a server to install your first web server
- you need to ssh to your server and start working

- few ftp clients
  - transmit
  - cyberduck
  - filezilla


```sh
# using linux package manager
$ sudo apt-get update
$ sudo apt-get install nginx

$ sudo yum install epel-release
$ sudo yum install nginx

# start the nginx service if not already installed
$ service nginx start

# or
$ systemctl start nginx

# check nginx process is running or not!
$ ps aux | grep nginx
```

ps = list down the processes
 - a = all user processes
 - u = list details infromation
 - x = list boot processes

all the nginx related configuration information is stored in `ls -l /etc/nginx` directory

### Prefered method of installing nginx

installing nginx from sources gives us the ability to customize the nginx based on our needs and extends nginx functionality that 

```sh
$ apt-get update
# download the nginx source
$ wget http://nginx.org/download/nginx-1.13.10.tar.gz
# extract the tar archive
$ tar -czvf nginx-1.13.10.tar.gz
$ cd nginx-1.13.10
$ apt-get install build-essential
# compile source code
$ ./configure
$ apt-get install libpcre3 libpcre3-dev zlib1g zlib1g-dev libssl-dev

# configuring nginx
$ ./configure --sbin-path=/usr/bin/nginx --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log ---http-log-path=/var/log/nginx/access.log --with-pcre --pid-path=/var/run/nginx.pid --with-http_ssl_module

# compile configuration src
$ make

# install compiled src
$ make install 

# For CentOS
$ yum check-update
$ yum groupinstall "Development Tools"
$ yum install pcre pcre-devel zlib zlib-devel openssl openssl-devel

```
IMPORTANT RESOURCES
- nginx.com
- nginx.org

Note nginx modules comes in two forms
- bundeled modules
  - gzip, spdy, ssl, geoip
- 3rd party modules
  - maintain and developed by 3rd party software firms and can be downloaded and used

### Adding an Nginx Service

we would use systemd (freedesktop.org) for manage and making our apps standerized like a standard way of starting, stopping and restarting service. Not only that it also helps to to auto start after boot


following command shows list of commands available to nginx service
`$ nginx -h`

following command is used to send signal to nginx
`$ nginx -s [start,stop,reload]`

You can get inti scripts from nginx.com under init scripts section

/lib/systemd/system/nginx/service
```conf
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi0user.target
```


A better way of managing services
```sh
# display resources used by nginx
$ systemctl status nginx
$ systemctl start nginx
$ systemctl enable nginx
```

## Configurating Nginx

terminology used in nginx configuration
- context ~ scopes ~ block
- directives


directive is specific configuration options for example `server_name mydomain.com;`. it is generally in the form of key value pairs

where context is considered as block or section in configuration files generally with in curly brases {}

context has scopes, they can be nested, and apperently inherit from parent/outer scope

context in nginx
- main
  - http
    - server

we have main context, inside of it we have http context and inside of it we have server context.

in the main context we specify global directives that are applied to master process

```conf
user www www;
worker_processes auto;
error_log logs/error.log;
pid logs/nginx.pid;

events {
  worker_connections: 4096;
}

http {
  index index.html index.htm index.php;
  include mime.types;

  # virtual host
  server {
    listen 80;
    server_name mydomain.com;
    access_log /var/log/mydomain.com.access.log main;
    root html;

    location /some_path {
      add_header header_name header_value;
    }
  }
}
```


### Creating virtual host
1. open configuration file `$ nano /etc/nginx/nginx.conf`
2. remove everything and start writing from scratch

```conf
events {}
http {

  # types {
  #   text/html html;
  #   text/css css;
  # }
  
  # instead of defining the mime types of the files by ourselfs we should include it
  include mime.types;

  # virtual host or server context
  server { 
    listen 80;
    server_name *.domain.com;

    # root path from which nginx will server the requests - interperting static requests
    root /sites/demo;
  }
}
```
3. reload the configuration `$ systemctl reload nginx`

Note: '*.mydomain.com' will accept connections from any sub-domain eg. app.mydomain.com, portal.mydomain.com, gateway.mydomain.com

Note: if the domain name of the web server is not configured you can use ip address of the server as server_name

Note: if someone requests for /images/cat.png the nginx by default search the file from root defined. If the root is defined as: /root/path then fully specified path will look like this: /root/path/images/cat.png

Note: be aware of the wrong content type header when requesting for some resource. Mime-type error - A great way to debug the wrong content type headers
`$ curl -I http://localhost:80/styles.css`

show pre defined mimetypes to include
`$ cat /etc/nginx/mime.types`

The listen directive can be set to
- an ip-address/port combo
- alone ip-address which listens on default port 80
- alone port which listens to every interface on that port
- path to UNIX socket

When incomplete listen directive
- a block with no listen directive uses the value 0.0.0.0:80
- a block set to an ip-address with no port will listen to xxx.xxx.xxx:80
- a block set to port 8888 only will listen to 0.0.0.0:8888


Nginx evaluates the `server_name` directive by following formula
- nginx first tries to find the server block with a server name matches the value in the "HOST" header of the request exactly
- find a server block with the `server_name` matching using a leading wild-card (indicated by the * in the begining of the name in the config)
- if no match is found using a leading wild-card, then nginx will look for the `server_name` that matches using trailing wildcard
- if no match is found using a trailing wildcard, Nginx then evaluates server blocks that define the server_name using regular expressions (indicated by a ~ before the name)
- If no regular expression match is found, Nginx then selects the default server block for that IP address and port.


nginx allows us pieces of configuration to include to our main configuration file.


### Using Location Blocks

- most used context in any of the nginx configuration
- using location directives we define the behaviour of each URIs we define.
- you can think of location blocks intercepting each incomming requests based on its value, and doing something other then just trying to serve a matching file relative to root dir.


syntax:
```conf

location optional_modifier location_match {

}
```

#### Options - optional_modifier
- (none): The location is interpreted as a prefix match. This means that the location given will be matched against the beginning of the request URI to determine a match.
- =: This block will be considered a match if the request URI exactly matches the location given.
- ~: This location will be interpreted as a case-sensitive regular expression match.
- ~*: The location block will be interpreted as a case-insensitive regular expression match.
- ^~: If this block is selected as the best non-regular expression match, regular expression matching will not take place.

```conf
server {
  # prefix match
  location /greet {
    return 200 "hello from nginx";
  }
  # exact match
  location = /exact {
    return 200 "exact match path";
  }
  # REGEX match - case sensitive
  location ~ /regex[0-9] {
    return 200 "regix match path";
  }
  # REGEX match - case in-sensitive
  location ~* /iregex[0-9] {
    return 200 "regix match path - case insensitive";
  }
  # Preferential Prefix match
  location ^~ /igreet2 {
    return 200 "preferential greet match";
  }
}
```

- nginx assigns priority to the location blocks thats you configure based on modifiers, unlike the order in which you specify the location blocks. Regular expressions blocks have higher precedence than prefix match blocks.


it is important! to understand the priority and order in which nginx matches the requests.

1. exact match = uri
2. Prefential Prefix match ^~ uri
3. REGEX match ~* uri
4. Prefix match uri

### Nginx variables

types of variables in nginx
- variables we set eg. `set $var 'something'`
- variables by nginx eg. `$http $uri $args`

you can see the list of all variables provided by the nginx from the nginx documentation. https://nginx.org/en/docs/varindex.html


/inspect?name=ali

```conf
server {

  # checks static API key
  if ($arg_apikey != 1234) {
    return 401 "incorrect api key";
  }

  set $weekend 'No';

  # check if weekend
  if ( $date_local ~ 'Saturday|Sunday' ) {
    set $weekend 'Yes';
  }

  location /is_weekend {
    return 200 "$weekend";
  }

  location /inspect {
    return 200 "hostname: $host \npath: $uri \nquery: $args \nindividual arg: $arg_name";
  }
}
```

NOTE: using conditionals inside location block is highly discouraged. Because it leads to indeterministic

#### Commonly used request variables
- $host
- $http_host
- $https | "on" if connection operates in SSL/TSL mode, or an empty string otherwise
- $request_method | request action verb eg. GET, POST, PUT, DELETE, PATCH ...
- $request_uri | full original request URI with arguments
- $scheme | request scheme http/https
- $server_name | name of the server which accepted the request
- $server_port | port of the server which accepted the request

### Rewrites or Redirects

for redirects or rewrites we use following directives
- `rewrite pattern-match newURI`
- `return status newURI`

NOTE: all 3xx status are redirects of some sort

eg. return 307 /some/path;
eg. return 307 /thumb.png;


```conf

server {

  root /sites/demo;

  # the ^ here represents REGEX pattern starting with
  # writing rewrites before matching any location
  # (\w+) represents REGEX capture groups that we get by $1
  rewrite ^/user/(\w+) /greet/$1; 
  rewrite ^/greet/john /thumb.png;

  # specifies no more rewrites after this.
  rewrite ^/greet/new /hello.png last;

  location /logo {
    return 307 /thumb.png;
  }
  location = /greet/jhon {
    return 200 "Hello Jhon";
  }
}

```

redirects tells where to go instead. eg. 307 means temporarly redirected.

NOTE: in rewrites request is written internally in contrast to the redirects 

NOTE: when a uri is re-written it also gets re-eveluated by nginx as completely new request. rewrites has some sort of performance issues because it takes some extra resources.


Another important and powerfull feature of rewrites is the ability of capture certain paths of the original URI using std regular expression capture groups. () as $1 or $2


### Try-Files & Named Locations

- techanically 3rd type of redirect directive
- could be used in server context or location context

```conf
server {

  # will be applied to all files...
  # this directive intercepts every requests and checks for the paths in cronological order. If it founds the path relative to the root it sends it to the client.
  try_files path1 path2 final;
  
  
  location / {
    try_files path1 path2 final;
  }
}
```

nginx will find the files path relative to the root directory with the final argument as redirect


- when try_files reaches its last path it is then treated as internal rewrite.
- we can use nginx variables with try_files directive as `try_files $uri /404`;
- try_files will only check the paths relative to the root directive

> NOTE: `try_files` is an internal requests like. error_page, index, and random_index.


```conf
server {

  try_files $uri /404;

  location = /404 {
    return 404 "sorry, that file could not be found.";
  }
}
```

Named location means assigning a name to the location context and telling a directive such as try_files to use its name instead of its location path ensureing no re-eveluation.

```conf
server {
  try_files $uri @404;
  location @404 {
    return 404 "No file found with that name";
  }
}
``` 

### Logging

nginx provides 2 log types
- Error logs (Failed logs, that didn't happened as expected)
- Access Logs

- Logs generally allows us track errors and identify malicious users.
- We can also add resource specific logs.

by default nginx logs are stored at `/var/log/nginx/`

a properly handled 404 can not create entry in error.log

- we can also enable or disable logging
- we can use miliple logs directive inside any context.

```conf
server {
  listen 80;
  root /sites/demo;
  location /secure {
    access_log /var/log/nginx/secure.access.logs;
    # disable logs
    access_log off;
    return 200 "Welcome to the secure area";
  }
}
```

for more advance we generally specify the format of the logs entries, gzip, flush-time, conditions etc...

### Inheritance and Directive Types

nginx inherits configuration from its parent block or scope

eg.
```conf
server {
  root /sites/demo;
  location {
    # inherited root
    # root /sites/demo;
  }
}
```

in nginx inheritance is not always straight forward and will vary depends upon the directive being used.

Types of directives:
- Standard Directive
- Array Directive
- Action Directive

```conf
#########################
# (1) Array Directive
#########################
# Can be specified multiple times without overriding a previous setting
# Gets inherited by all child contexts
# Child context can override inheritance by re-declaring directives
access_log /var/log/nginx/access.log;
access_log /var/log/nginx/access.log custom_format;

http {

  server {
    listen 80;
    server_name site2.com

    ##########################
    # (2) Standard Directive
    ##########################
    # Can only be declared once. A second declaration overrides the first
    # Gets inherited by all child contexts
    # Child context can override inheritance by re-declaring directives;
    root /sites/site2;

    # Completely overrides inheritance from (1)
    access_log off;

    location /images {

      try_files $uri /stock.png;
    }

    location /secret {
      ########################
      # (3) Action Directive
      ########################
      # Invokes an action such as a rewrite or redirect
      # INheritance does not apply as the request is either stopped (redirect/response) or re-evaluated (rewrite)
      return 403 "You do not have permission to view this.";
    }

  }
}
```

### PHP Processing


up to now we configured nginx to server static files by leaving the handling of the files by client or browser based on its mime type


as we know nginx is n't able to embed server side language processors. Inorder to achieve that we use stand alone php servers like php-fpm to wihich nginx parse the request for processing. and get parsed response and send it to client.


Install php latest stable release
```sh
$ apt-get update
$ apt-get install php-fpm

# list systemd units
$ systemctl list-units | grep php
```

```conf

user www-data;
http {

  server {
    listen 80;
    root /sites/demo;
    index index.php index.html;

    # will serve the static files
    location / {
      try_files $uri $uri/ =404;
    }
    location ~\.php$ {
      # pass php requests to the php-fpm server
      # using fast CGI protocol
      include fastcgi.conf;
      fastcgi_pass unix:/run/php/php7.1-fpm.sock
    }
  }

}
```

Fast cgi portocol is the protocol like http but it is used to transfer binary data. we can use standard http protocol but fast-cgi is relatively faster

A unix socket is created by php-fpm. Think of the socket as http port a file on which a server can listen for binary data.


```sh
$ find / -name *fpm.sock
$ echo '<?php phpinfo(); ?>' > /sites/demo/info.php
```

NOTE: check the error.log if something went wrong.

```sh
# check process full information
$ ps aux | grep php
$ ps aux | grep nginx
```

### Worker processes

check system processes
```sh
$ systemctl status nginx
$ ps aux | grep nginx
```

master process is the actual server instance, then this master process created worker processes for processing response.

to change the no of worker processes write following line to the main context.
```conf
worker_processes 2;

# will set worker processes to the number of cores available at host machine
# worker_processes auto;
```

IMPORTANT: 99% of the time we set the worker processes equal the no of cores available to the host machine.

increasing the number of worker processes in hope that our server will perform better


the worker process handles the requests asynchronously means as far as the hardware is capable of. 


to get the number of cores available run the following command
```sh
$ nproc
```

to get more detailed information of cpu
```sh
$ lscpu
```

setting no of connection that each worker process can handle

```conf
user nginx;
pid /var/run/nginx.pid;
worker_processes auto;
events {
  worker_connections 1024;
}
http {
  ...
}

 ```

check the file limit that the OS can handle
```sh
$ ulimit -n
```

max connections = worker_processes * worker_connections


### Buffers & Timeouts

```conf
user nginx;
worker_processes auto;
events {
  worker_connections 1024;
}
http {
  include mime.types;

  # Buffer size for POST submissions
  client_body_buffer_size 10k;
  client_max_body_size 8m;

  # Buffer size for Headers
  client_header_buffer_size 1k;

  # Max time to recieve client headers/body
  client_body_timeout 12;
  client_header_timeout 12;

  # Max time to keep a connection open for
  keepalive_timeout 15;

  # Max time for the client accept/recieve a response
  send_timeout 10;

  # skip buffering for static files
  sendfile on;

  # optimize sendfile packets
  tcp_nopush on;

  server {
    ...
  }
}
```


Buffering hear means when nginx worker process reads data into memory before writing it to its destination

Timeouts simply means cutoff time for the particular event eg. if recieving a request from client stops for some reason in the middle. Timeouts helps our server to stop endless stream of data to recieve in case someone attacks our server.

buffer_directive 100 - bytes
buffer_directive 10k - kilobytes
buffer_directive 10m - megabytes

if incase POST request have body of size more than 8m the server will sent 413 'Request Entity too large' 

timeout_directive 30 - milliseconds
timeout_directive 30s - seconds
timeout_directive 30m - minutes
timeout_directive 30h - hours
timeout_directive 30d - days


### Adding Dynamic Modules

[PAGESPEED]
[SSL]
[NGINX]

the difference between the static and dynamic module is that dynamic module are loaded on runtime while static modules are loaded at once 

Dynamic modules are very useful for small but useful tasks such as resizing imaging before sending it to client. etc...

## Performance

### Headers & Expires

- setting the response expire headers tells the client(borwser) how long it can cache the response for. eg. logos, assets, styles-sheet etc...

```conf

location = /thumb.png {
  add_header my_header "Hello world";
  # telling the receiving client that this resource or response can be cached in any way
  add_header Cache-Control public;
  # older version of above
  add_header Pragma public;
  # tells that response can vary based on the value of the request header 'Accept-Encoding'
  add_header Vary Accept-Encoding;
  # set the expire header
  expires 60m; # m = minute; M = month; h = hour
}

# a practical example
location ~* \.(css|js|jpg|png)$ {
  access_log off;
  # your cache control headers
}

```

```sh
# check headers with curl
$ curl -I http://localhost:80/thumb.png
```



### Compressed Response with gzip

- extends the delivery of static resources one step further using compressed response

```conf
http {
  # step 1. enable compression on http module
  # inherited in the child contexts
  gzip on;
  gzip_comp_level 4; # range from 0-9 higher the number greater the compression hence smaller size but more server resources are required.
  gzip_types text/css text/javascript;

  location ~* (css|js|jpg|png)$ {

    add_header Cache-Control public;
    add_header Pragma public;
    # now this header will triger the response being compressed or not!
    add_header Vary Accept-Encoding;
    expires 60m;
  }

}

```

```sh
# debug the response by sending "Accept-Encoding" header
$ curl -I -H "Accept-Encoding: gzip, deflate" http://localhost:80/styles.css

# check the compressed response - terminal will complain
$ curl -H "Accept-Encoding: gzip, deflate" http://localhost:80/styles.css

```


### FastCGI cache

- micro cache is simple server side cache that stores dynamic language responses inorder to minimize server load.

           [micro]
           [cache]
              |
[browser]---[nginx]---[php]---[DB]

- cache dynamic content will dratically increase the proformace of your application but it is not always simple and straight forward to implement.

```conf

http {

  # configure microcache fastcgi
  # tells the path to store the cache entries
  # levels defines the depth of the cache being saved
  # in-active sets how long a cache is stored until the last time it accessed
  fastcgi_cache_path /tmp/nginx_cache levels=1:2 keys_zone=ZONE_1:100m incative=10m;
  # cache naming convention/format which is then being hashed eg. md5-hash
  fastcgi_cache_key "$scheme$request_method$host$request_uri";

  # add custom header that tells the response is server from cache or not
  add_header X-Cache $upstream_cache_status;

  server {

    listen 80;
    server_name mydomain.com;

    root /sites/demo;
    index index.php index.html;

    # Adding cache exceptions (important part of dynamic content cashing)
    # Cache by default
    set $no_cache 0;

    # if ($request_method = POST) {
    #   # add no cache for POST requests
    # }

    # expecting from query params to bypass cache
    if ($arg_skipcache = 1) {
      set $no_cache 1;
    }

    location / {
      try_files $uri $uri/ =404;
    }

    # files ending with php
    location ~\.php$ {
      include fastcgi.conf;
      fastcgi_pass unix:/run/php/php7.1-fpm.sock;

      # enable cache
      fastcgi_cache ZONE_1;
      fastcgi_cache_valid 200 60m;
      fastcgi_cache_valid 400 10m;
      # bypass or skip cache and donot save response to cache respectively
      fastcgi_cache_bypass $no_cache;
      fastcgi_no_cache $no_cache;
    }

  }

}

```

level parameter defines the logic for splitting of the cache entries
eg. 1:2 represents an entries like this.

2 [last digit]
  0b [last 2 digits]
    342fe233ec1400d40b2 [md5 hash]
4
  cc
    3d323acf3232dac3cc4

keys_zones defines the name of the zone with size of the cache zone 

inactive defines how long the entries are keep cached until its last accesses [default=10m]

$scheme = https
$request_method = GET
$host = domain.com
$request_uri /blog/article

#### Apache Bench
Apache Bench is the simple Http server benchmarking tool

```sh
# install on debian
$ apt install apache2-utils
# install on centos
$ yum install httpd-tools

# show the tool help
$ ab --help

$ ab -n 100 -c 10 http://localhost
```

```sh
$ curl -I http://localhost:80/?skipcache=1
```

NOTE: we can add this exception of not to cache for anything like logged-in areas of your site, live-data etc...

NOTE: caching server site content could be the single bigges performance enhancement that can be added to your site.


### Http 2

- as of version 1.9.5 nginx include new http 2 module

Difference between http2 and http1.1
- http2 is binary protocol where http 1.1 is textual protocol
- Compressed headers
- Persistent connections
- Multiplex Streaming (html,css,js could be combined into single stream of binary data)
- Server push

NOTE: opening a new connection is a time consuming task, that is why most of the developers concatinate multipe javascript or css files into single file.

How many number of connections could be open with perticular domain


REMEMBER: http 1.1 process simplex streaming(one connection handles one request)

for a simple page an average 15 connection is common. But it also decreses the browser capability of handling that much connections.


- enable and configure HTTP2
- requirement for Http2 is SSL or HTTPs

- we can configure and use 3rd party verdors certificates like lets-encrypt


generating new self signed certificate
```sh
$ mkdir /etc/nginx/ssl
# making a new cerfificate request of standard x509 having validy of 10 days, nodes which allows us to leave a pass phrase for the key file, generate a new private key
$ openssl req -x509 -days 10 -nodes -newkey rsa:2048 -keyout /etc/nginx/ssl/self.key -out /etc/nginx/ssl/self.crt 
```

```conf

http {

  include mime.types;

  server {
    # setting up ssl and http2 modules
    listen 443 ssl http2;

    ssl_certificate /etc/nginx/ssl/self.crt;
    ssl_certificate_key /etc/nginx/ssl/self.key;

    server_name localhost;
    root /sites/demo;

    index index.php index.html;

    location / {
      try_files $uri $uri/ index.html;
    }

    location = /index.html {
      # server push following resources
      http2_push /style.css;
      http2_push /thumb.png;
    }

  }

}

```

### Server push of HTTP2


a terminal based http2 client for debugging the response, because native browser inspecting network tab is not capable enough to show http2 based request-response 
```sh
$ apt install nghttp2-client

# n = discard the response from saving
# y = ignore the self signed sertificate
# s = print statistics
# n = also get linked resources
$ nghttp -nysn https://localhost
```

## Security

### HTTPs (SSL)

the first step in enabling ssh is providing some kind of fallback handler for in secure http connection

By default the http request goes to port 80 if port is not defined in the url

https now a days becomes standard and there is no legetimic reason of using http any longer

```conf

http {

  # create a virtual server for redirecting http traffic to https  
  server {
    listen 80;
    server_name mydomain.com;
    return 301 https://$host$request_uri;
  }

  server {
    listen 443 ssl http2;
    server_name mydomain.com;

    root /sites/demo;
    index index.html;

    ssl_certificate /etc/nginx/ssl/self.crt;
    ssl_certificate_key /etc/nginx/ssl/self.key;

    # Disable SSL
    ssl_protocols TLSv1 TLSv1.1 TLS1.2;

    # Optimise cipher suits
    # algorithms names seperated by : with indication ! to specify not to use
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDH+AESGCM:ECDH+AES256:ECDH+AES128:DH+3DES:!ADH:!AECDH:!MD5;

    # Enable DH Params - allows server to exchange keys btw server and client with perfect secriticty - very good addition to enhance security
    ssl_dhparam /etc/nginx/ssl/dhparam.pem;

    # Enable HSTS - Strict transport security - header that tells the client not to load content over http
    add_header Strict-Transport-Security "max-age=31536000" always;

    # SSL sessions - cache handshake data for set ammount of time - imporves performance - default is 'builtin' - only limited to worker process
    ssl_session_cache shared:SSL:40m;
    ssl_session_timeout 4h;
    ssl_session_tickets on;


    location / {
      try_files $uri $uri/ =404;
    }
  }

}

```

generating dh param file
```sh
$ openssl dhparam 2048 -out /etc/nginx/ssl/dhparam.pem

$ systemctl reload nginx
```


SSL is an older version of securing website. TSL is the newer and better version to to same function more securely and reliabily.

SSL(secure socket layer) is outdated and replaced by TSL(transport security layer)

Most important list of increase security of your nginx servers
- Disable SSL use TLS only
- Optimise Cipher Suits
- Enable DH params
- Enable HSTS
- Cache SSL sessions

### Rate Limiting

- rate limiting could be considered as traffic lights for incomming requests.
- rate limiting is the server implies other then simply limiting manageing incomming connection for specific reasons.
- Common Reasons
  - Security - Brute Force Protection
  - Reliability - Prevent Traffic Spikes
  - Shaping - Service priority based on tier eg. download servers


we will use SIEGE a new command line tool for testing load on a server ruther then banchmarking the server (minor difference btw the two)

```sh
# install the required software
$ apt install siege

# v = verbose
# r = run x tests
# c = of y concurrent connections
$ siege -v -r 2 -c 5 http://localhost/thumb.png

```


```conf

http {

  # Define limit zone
  # here rate limiting is applied on requestor ip address
  limit_req_zone $binary_remote_addr;
  # here rate limiting is applied on server name
  # limit_req_zone $server_name;
  # here rate limiting is applied on requesting uri
  # 60 requests per minute = 1 request per second
  # NOTE: this doesn't means that server can accept 60 requests at onces and then no more for the remainder of the minute - but rather it set the frequency of that time frame
  limit_req_zone $request_uri zone=MYZONE:10m rate=60r/m;

  # setting burst limit - changes the behaviour of imediately rejecteing the requests to allow to x number;
  limit_req_zone $request_uri zone=MYZONE:10m rate=1r/s burst=5;


  server {
    listen 80;

    location / {
      limit_req zone=MYZONE;
      # or we can apply burst here
      # nodelay is optional param
      # limit_req zone=MYZONE burst=5 nodelay;
      try_files $uri $uri/ =404;
    }
  }

}

```

### Baisc Auth

let say you have some area of your web site that requires only authorized person to access eg. /admin

basic auth provides simple user-name and password layer to any part of your site.

```sh
$ apt install apache2-utils
# or
$ yum install httpd-tools

# c = we want written password written to a file for a given user
$ htpasswd -c /etc/nginx/.htpasswd user1
```


```conf

http {
  server {
    listen 80;

    location /secure {
      auth_basic "Secure Area";
      auth_basic_user_file /etc/nginx/.htpasswd;
    }
  }
}

```

### Hardening NGINX

in cyber world attacks are common and sooner or later venulabilites emerges as we move on. It is good practice to adopt regular security updates to your server inorder to secure it from new velunabilities. 


```sh
$ nginx -v
$ apt update
$ apt upgrade
```

we can disable version information of our nginx server by

```conf

http {

  # disable nginx version information in resp
  server_tokens off;

  server {
    # disable click clickjecking
    add_header X-Frame-Options "SAMEORIGIN";
    # enable cross site protection
    add_header X-XSS-Protection "1; mode=block";

  }

  ...
}

```

- last step is to removing unused or dangerous nginx modules that includes potential security risks


### LetsEncrypt SSL Certificates

- free, automated, and open sertificate authority.
- encourages the use of https over http

in order to generate certificate and automate the re-newal we use a tool called certbot.

Let's Encrypt + CertBot + Nginx =  Love

NOTE: Let's encrypt won't issue certificate for ip addresses - a valid domain is required

1. install certbot

```sh
$ goto certbot.eff.org
# selecte relavent server software and the currosponding OS

# Follow the instruction appeared
$ apt update
$ apt install software-properties-common
$ apt add-repository ppa.certbot/certbot
$ apt update
$ apt install python-certbot-nginx

# check certbot is installed or not.
$ certbot --help
```

```sh
# cerbot will inspect your nginx.conf file and enable ssl by its own
$ certbot --nginx 

# list generated certificates
$ ls /etc/letsencrypt/yourdomain.com

# check your nginx.conf file
# here you see list of lines added by certbot ending with a comment 'managed by CertBot'
$ cat /etc/nginx/nginx.conf

# renew certificates when required
$ certbot renew

# force renewal
$ certbot renew --dry-run

# a simple cron job that try to renew certificate daily if expired
$ crontab -e
    ADD THE FOLLOWING LINE
    @daily certbot renew

```

## Reverse proxy and load balancing

load balancing and reverse proxy are the features that nginx provides as a web server.

```conf
events {}

http {

  server {
    listen 8088;

    location / {
      return 200 "Hello from nginx";
    }
  }
}

```

```sh
$ nginx -c /path/to/nginx/conf
```

create php server
```sh
# by default will server the directory in which it runs from
$ php -S localhost:9999;

$ php -S localhost:8888 file.txt
```

### Nginx as a reverse proxy


A reverse proxy in simple words acts as an intermediatery between client(browser) and the resource(servers).

                nginx
[client] -- [reverse-proxy] -- [server]

A reverse proxy acts as an agent that interprets the client requests, passes them to required server (php, node, .net, ruby) and get the response and sent back (reverse) it to client.

all the request will go to and from the reverse proxy (nginx) server.


```conf 

server {
  listen 8088;

  location / {
    return 200 "hello from NGINX";
  }

  # trailing slash '/' is important to add. 
  # because if we won't include it the whole location path '/php' would be visible to the end.
  # if we don't specify the trailing '/' nginx will assume the original request path.
  # we can create different use cases for different purpose but it is recommended to use trailing slash because it is less confusing
  location /php {
    proxy_pass 'http://localhost:9999/';
  }

  # a completely remote site as we are visiting original website directly
  location /nginxorg {
    proxy_pass 'https://nginx.org/';
  }

}

```

there is no limitation or restriction to the proxy server(s) being on the same system 


show_request.php
```php
<?php
  echo 'Path: ' . $_SERVER['REQUEST_URI']; 
>
```

```sh
# start the server which will serve the following file
$ php -S localhost:9099 show_request.php
```

if we curl the server
```sh
$ curl http://localhost:8088/php/some/path
```

`//some/path` will be recieved to the receiving server. Path after what is defined in nginx conf. Don't worry the double trailling slash will be normalized on the server and should not cause any issue.

another important expect of using nginx as a reverse proxy is passing custom header either to our proxy server or to the client.

```conf 

  server {
    listen 8088;

    location /php {
      # sent it to the client only
      add_header proxied nginx;
      # sent it to the proxied server only
      proxy_set_header proxied nginx;
      proxy_pass 'http://localhost:4000/';
    }
  }

```

show_request.php
```php
<?php
  ehco "display php headers: " . var_dump(getallheaders());

>

```

### Load Balancer

nginx make it easy to configure and robust load balancer.
                      / --[server-B]
                     / 
[client] ---- [load-balance] ---- [server-A]
                    \
                      \ --[server-C]

A load balancer should achieve 2 main objectives
1. the ability to distribute request to multiple servers (reducing the load of individual servers)
2. to provide redudency (for what ever reason if any of our server fails nginx automatically redirects traffic to other servers)


```php
echo "Hello from 1st";
```

```sh
# Starting multiple servers
$ php -S localhost:9001 first.php
$ php -S localhost:9002 second.php
$ php -S localhost:9003 third.php
```

test the running servers individually
```sh
curl http://localhost:9001
```

load balancing

```conf

events {}

http {

  # grouping the servers together
  # the default algorithm that is used in load balancing is round robin
  upstream php_servers {
    server localhost:9001;
    server localhost:9002;
    server localhost:9003;
  }

  server {
    listen 8088;

    location / {
      proxy_pass http://php_servers;
    }

  }
}

```

```sh
$ curl http://localhost:9001

# a quick way
$ while sleep 0.5; do curl http://localhost:8088; done
```

we have to create up-stream context/block that adds several servers with the ability to add some options to it - think of it as named collection of servers that shared commonality - in most of the time serves the same content


### Load Balancer Options

load balance based on differenct criteria

- sticky sesstions - ip hash
    here connected clients are stick to the single server always. Request is bound to user ip address and always when possible proxy to the same server. Usefull for maintaining user login sessions. Very usefull for loadbalancing websites or services that rely heavily on server sessions or session state.
- least connections 
    distribute load based on least number of conections intellegently

```conf 
http {

  upstream php_servers {
    # defining the load-balance algorithm
    ip_hash;
    # least_conn;
    server localhost:9001;
    server localhost:9002;
    server localhost:9003;
  }

}
```

### Adding an NGINX init service
download the inti script form [here](https://wiki.nginx.org/initScripts) - download the init script of your installed OS

```sh
$ cd /etc/init.d/
$ wget url-here

$ sudo chmod +x nginx
# load the init script
$ update-rc.d -f nginx defaults
```

### Geoip

0. enable geoip module by `--with-http_geoip_module`
1. goto: dev.maxmind.com
2. download the geolite lagacy free downloadable database for country and city (camptable with nginx)
3. extract the downloadable resources to /etc/nginx/geoip

```conf 

http {

  # geo ip confi
  geoip_country /etc/nginx/geoip/GeoIp.dat;
  geoip_city /etc/nginx/geoip/GeoLiteCity.dat;

  server {
    listen 8088;

    # list available variables that could be used with this.
    # https://nginx/org/en/docs/http/ngx_http_geoip_moduel.html

    location /geo-country {
      return 200 "You are from $geoip_country_name";
    }

    location /geo-city {
      return 200 "You are from $geoip_city";
    }

  }
}
```

### Video streaming

0. add module `--with-http_mp4_module`


```conf

  server {
    listen 8088;

    location ~ \.mp4$ {
      root /sites/downloads;
      mp4; # define the mp4 module
      # control variables
      mp4_buffer_size 4M;
      mp4_max_buffer_size 10M;
    }
  }

```


### Resources
- https://nginx.org/en/docs
- https://nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/
- https://digitalocean.com/community/search?q=nginx
- https://codex/wordpress.org/Nginx
- https://github.com/fcambus/nginx-resources
- https://vishnuch.tech/nginx-cheatsheet
- https://lzone.de/cheat-sheet/nginx
- https://www.docdroid.net/ooD0qnV/nginx-cheat-sheet-pdf
- https://github.com/SimulatedGREG/nginx-cheatsheet