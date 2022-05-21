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