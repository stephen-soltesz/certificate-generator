# certificate-generator
Sample AppEngine service to generate ssh host keys

```
for key in ed25519 rsa ecdsa ; do
    echo $key
    # Download key.
    curl -s --output /etc/ssh/ssh_host_${key}_key \
        -XPOST http://localhost:8080/v1/certgen/mlab1.foo01/ssh/$key

    # Generate public key.
    ssh-keygen -y -f /etc/ssh/ssh_host_${key}_key > /etc/ssh/ssh_host_${key}_key.pub

    # Set permissions.
    chmod 0600 /etc/ssh/ssh_host_${key}_key
done

for key in ed25519 rsa ecdsa ; do
    echo $key
    ssh-keygen -l -f /etc/ssh/ssh_host_${key}_key.pub
done

ssh-keyscan localhost > keys
ssh-keygen -l -f keys
2048 0b:f1:a6:df:53:43:f9:22:ae:2c:53:3b:6b:df:02:e2 localhost (RSA)
521 14:ff:06:b6:27:94:11:a4:16:5d:5f:1c:e9:d6:99:b9 localhost (ECDSA)
256 4e:74:31:6f:08:43:1d:03:ae:07:01:1c:ca:c0:be:87 localhost (ED25519)
```
