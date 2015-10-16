rem From NIST
rem The recommended key length for data which should be available > 2016
rem is 2048 (RSA)

c:\OpenSSL-Win32\bin\openssl.exe genrsa -out ..\build\ca.key  4096
c:\OpenSSL-Win32\bin\openssl.exe req -new -x509 -nodes -sha1 -days 3650 -key ..\build\ca.key -out ..\build\ca.crt -config ca.conf
c:\OpenSSL-Win32\bin\openssl.exe x509 -trustout -inform PEM -in ..\build\ca.crt -outform DER -out ..\build\ca.pfx
