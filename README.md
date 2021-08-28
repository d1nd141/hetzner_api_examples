# knockd_firewall.py
This will allow you to open the Hetzner cloud firewall using an API request.
I use this script with knockd:

```
[ALL]
        sequence    = xxxx:udp,xxxx:udp,xxxx:tcp
        seq_timeout = 5
        start_command     = /opt/scripts/knockd_firewall.sh --action=add --ip=%IP%
        stop_command     = /opt/scripts/knockd_firewall.sh --action=del --ip=%IP%
        tcpflags    = syn
        cmd_timeout = 3600
```
