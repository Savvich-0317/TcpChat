cd keys
ssh-keygen -t rsa -b 4096 -m PKCS8 -f rsa_key -N ""
ssh-keygen -f rsa_key.pub -e -m PKCS8 > rsa_key_public.pem
