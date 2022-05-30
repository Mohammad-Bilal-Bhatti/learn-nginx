# Nginx Fundamentals

Metadata
- Course started date: 22-May-2022 
- Course ended date: 
- Instructor: 
- Source: Udemy

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


nginx allows us pieces of configuration to include to our main configuration file.


### Using Location Blocks

- most used context in any of the nginx configuration
- using location directives we define the behaviour of each URIs we define.
- you can think of location blocks intercepting each incomming requests based on its value, and doing something other then just trying to serve a matching file relative to root dir.

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

