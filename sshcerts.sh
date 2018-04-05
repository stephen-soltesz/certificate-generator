#!/bin/bash


# CREATE CERT
ssh-keygen -b 4096 -t rsa -f measurement-lab-ssh-ca -C "CA key for SSH on measurement-lab.org hosts"

# ADD TO KNOWN_HOSTS
# @cert-authority 192.168.0.109 <ca-public-cert>

# SIGNING HOST PUBLIC KEY (HOST CERT)
ssh-keygen -s measurement-lab-ssh-ca -h -n 192.168.0.109 -V +52w -I ubuntu-192-168-0-109 ssh_host_rsa_key.pub

# UPDATE SERVER /etc/ssh/sshd_config
# HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub
# TrustedUserCAKeys /etc/ssh/measurement-lab-ssh-ca.pub

# SIGNING USER PUBLIC KEY (USER CERT)
ssh-keygen -s measurement-lab-ssh-ca -n soltesz,root -V +52w -I soltesz-user ~/.ssh/id_personal.pub

# REMOVE ALL CERTS FROM SSH_AGENT
ssh-add -D

# ADD THEM BACK
ssh-add

# SSH TO 
ssh root@192.168.0.109
