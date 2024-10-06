#!/bin/bash -xe

#Declaring Variables
DB_NAME="wordpressdb"
DB_USER="wordpressuser"
DB_PASS="W3lcome123"
LB_DNS="https://dev.clixx-samuel.com"
EP_DNS="wordpressdbclixx.cfmgy6w021vw.us-east-1.rds.amazonaws.com"

exec > >(tee -a /var/log/userdata.log) 2>&1
 
##Install the needed packages and enable the services(MariaDb, Apache)
sudo yum update -y
sudo yum install git -y
sudo amazon-linux-extras install -y lamp-mariadb10.2-php7.2 php7.2
sudo yum install -y httpd mariadb-server
sudo systemctl start httpd
sudo systemctl enable httpd
sudo systemctl is-enabled httpd

## Mounting EFS
FILE_SYSTEM_ID=fs-0c7225b6c50e6deff
AVAILABILITY_ZONE=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
REGION=${AVAILABILITY_ZONE:0:-1}
MOUNT_POINT=/var/www/html
sudo mkdir -p ${MOUNT_POINT}
sudo chown ec2-user:ec2-user ${MOUNT_POINT}
echo "${FILE_SYSTEM_ID}.efs.${REGION}.amazonaws.com:/ ${MOUNT_POINT} nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,_netdev 0 0" | sudo tee -a /etc/fstab
sudo mount -a -t nfs4

## Verifying if EFS mounted correctly
if ! mount | grep -q efs; then
    echo "EFS mount failed" >> /var/log/userdata.log
else
    echo "EFS mount succeeded" >> /var/log/userdata.log
fi
sudo chmod -R 755 ${MOUNT_POINT}
 
##Add ec2-user to Apache group and grant permissions to /var/www
sudo usermod -a -G apache ec2-user
sudo chown -R ec2-user:apache /var/www
sudo chmod 2775 /var/www && find /var/www -type d -exec sudo chmod 2775 {} \;
find /var/www -type f -exec sudo chmod 0664 {} \;
cd /var/www/html
  
 
## Cloning repository
if [ -f /var/www/html/wp-config.php ]; then
    echo "Repository already exists..." >> /var/log/userdata.log
else
    echo "Now cloning repository..." >> /var/log/userdata.log
    git clone https://github.com/stackitgit/CliXX_Retail_Repository.git
    cp -r CliXX_Retail_Repository/* /var/www/html
fi 

# Replacing localhost URLs with RDS Endpoint in wp-config.php
sudo sed -i "s/define( 'DB_HOST', .*/define( 'DB_HOST', '$EP_DNS' );/" /var/www/html/wp-config.php

# Updating WordPress site URLs in RDS database
echo "Running DB update statement..." >> /var/log/userdata.log
RESULT=$(mysql -u $DB_USER -p'$PW' -h $EP_DNS -D $DB_NAME -sse "SELECT option_value FROM wp_options WHERE option_value LIKE 'CliXX-APP-NLB%';")

# Check if result is empty
if [[ -n "$RESULT" ]]; then
  echo "Matching values found. Proceeding with UPDATE query..." >> /var/log/userdata.log
mysql -u $DB_USER -p'$DB_PASS' -h $EP_DNS -D $DB_NAME <<EOF
UPDATE wp_options SET option_value ='$LB_DNS' WHERE option_value LIKE 'CliXX-APP-NLB%';
EOF
  echo "UPDATE query executed." >> /var/log/userdata.log
else
  echo "No matching values found. Skipping update..." >> /var/log/userdata.log
fi
 
## Allow wordpress to use Permalinks
echo "Now allowing WordPress to use Permalinks…" >> /var/log/userdata.log
sudo sed -i '151s/None/All/' /etc/httpd/conf/httpd.conf
 
##Grant file ownership of /var/www & its contents to apache user
sudo chown -R apache /var/www
 
##Grant group ownership of /var/www & contents to apache group
sudo chgrp -R apache /var/www
 
##Change directory permissions of /var/www & its subdir to add group write 
sudo chmod 2775 /var/www
find /var/www -type d -exec sudo chmod 2775 {} \;
 
##Recursively change file permission of /var/www & subdir to add group write perm
sudo find /var/www -type f -exec sudo chmod 0664 {} \;
 
##Restart Apache
sudo systemctl restart httpd
sudo service httpd restart
 
##Enable httpd 
sudo systemctl enable httpd 
sudo /sbin/sysctl -w net.ipv4.tcp_keepalive_time=200 net.ipv4.tcp_keepalive_intvl=200 net.ipv4.tcp_keepalive_probes=5

echo "End of Bootstrap!" >> /var/log/userdata.log
