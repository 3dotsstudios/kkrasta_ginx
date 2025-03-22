#!/bin/bash
#Install and update machine

if [ $# -ne 1 ]
then
  echo "Could not find domain. Specify it via parameter e.g. bash kkrasta_ginx.sh DOMAIN.com"
  exit 1
fi

domain=$1

echo "Ssl in process"

certbot certonly --expand --manual --register-unsafely-without-email --agree-tos \
  --domain "${domain}" \
  --domain "*.${domain}" \
  --preferred-challenges dns

# certbot certificates

if [ $? -ne 0 ]
then
  echo "SSl failed for domain $domain"
  exit 1
fi
DefaultSSLDir="/etc/letsencrypt/archive"

if [ ! -d "$DefaultSSLDir" ]; then
  echo "Cannot Find Default SSL Directory /etc/letsencrypt/archive"
  exit 1
fi

certFile=`find /etc/letsencrypt/archive -type f -printf '%T@ %p\n' | sort -n | grep "cert" | tail -1 | cut -f2- -d" "`

privkeyFile=`find /etc/letsencrypt/archive -type f -printf '%T@ %p\n' | sort -n | grep "privkey" | tail -1 | cut -f2- -d" "`

mkdir -p /root/kkrasta_ginx/kkrasta_ginx/config/crt/$domain
cp $certFile /root/kkrasta_ginx/kkrasta_ginx/config/crt/$domain/kkrasta_ginx.crt
cp $privkeyFile /root/kkrasta_ginx/kkrasta_ginx/config/crt/$domain/kkrasta_ginx.key

exit 0