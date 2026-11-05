====================================================================
           ZCLOCKID APPLIANCE - SYSADMIN TERMINAL OVERRIDES
====================================================================

Files in this directory are reserved exclusively for manual terminal 
administration and custom configuration drop-ins by Linux sysadmins.

The ZclockID Web GUI and REST Management API will NEVER overwrite, 
modify, or delete files in this directory.

Supported drop-ins:
- smb-custom.conf      : Custom Samba shares, auditing, or extra parameters
- radius-custom.conf   : Custom FreeRADIUS clients, modules, or attributes
- bind-custom.conf     : Custom BIND9 DNS zones, ACLs, or view definitions
- nginx-custom.conf    : Custom HTTP/HTTPS endpoints or proxy passes

To apply changes after editing:
- Samba      : sudo systemctl reload samba-ad-dc
- FreeRADIUS : sudo systemctl restart freeradius
- BIND9      : sudo rndc reload
- Nginx      : sudo nginx -t && sudo systemctl reload nginx
