rm *.pem

openssl req -x509 -newkey rsa:4096 -days 365 -keyout ca-key.pem -out ca-cert.pem -subj "/C=CA/ST=Ontario/L=Toronto/O=My Basement Inc./OU=My University/CN=haider/emailAddress=imanari9719@gmail.com"


echo "My self signed certificate"
openssl x509 -in ca-cert.pem -noout -text


openssl req -newkey rsa:4096 -keyout server-key.pem -out server-req.pem -subj "/C=CA/ST=Ontario/L=Toronto/O=My webserver/OU=My computer/CN=server/emailAddress=haider.sajjad@mail.utoronto.ca"


openssl x509 -req -in server-req.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem



<VirtualHost 192.168.10.100:443>
DocumentRoot /var/www/website
ServerName www.theServerFourFours.com
SSLEngine on
SSLCertificateFile /home/arnold/cert/mysitename.crt
SSLCertificateKeyFile /home/arnold/cert/mysitename.key
</VirtualHost>
