# QFX5130 MAC Limit event script
The Juniper QFX5130 (-32CD and -48C) does not have the ability to limit the number of MAC addresses on a port, unlike almost every switch made since the beginning of time.   Even the first Catalyst products by cisco could do this on the Cat 3003 using port security.  What is much worse here is Juniper/HPE (ick) says this is supported in the [Feature Explore](https://apps.juniper.net/feature-explorer/feature/7368?fn=MAC%20limit,%20MAC%20move%20limit,%20and%20persistent%20MAC%20learning%20with%20EVPN-VXLAN) for this product.   

The "through the grapevine" answer from HPE/Juniper is that they are using the Trident 4 SDK from Broadcom and this is a race condition as the TD4 needs to learn the MAC before limiting it.  This is a cop-out, SONiC on TD4 and heck even the Dell version of this function on the S5448F of this switch.  Arista and Nokia both have it working too.  

# Use
The script is designed to be run from the router as an event every minute.  This loop will run once every 15 seconds and dump the mac table, then find any matching interface exceeding the mac limit and shut them down.  There is quite a bit of error handeling in it, as if multiple violating interfaces are found, it will batch them in a single commit and if this fails, it will do each in a single commit.  There is locking to prevent multiple instances of this running as well. 

In testing it was found the mac table can be polled every second without much issue, and the switch is able to learn about 2k mac's per second.  By default this runs 4 times in the loop per minute, meaning the most number of macs which would be learned if a port floods random macs is about 30k.  This was thought to be a good trade off in terms of polling vs. cpu time.   Running it every minute means that if it crashes, it will be restart fast, and doesn't need to be kicked when changes are made to the script; changes will be picked up every 60s.   

You can limit interfaces in several ways, but they need to be listed.  The entire interface (IFD) or unit/subinterface (IFLS) can be addressed.  Regexs are supported to match mutiple interfaces.  There is a default limit of MACs wich can be set, and each interface can be set individually.  Note that if you set the interface MAC number you must enable the interface in INCLUDE_*_EXACT stanza too. 

When a violation is found the script will log this to the logger and shutdown the interface or subinterface. 

# Config

- On the qfx config add this:
	set system scripts language python3
	set event-options generate-event SixtySeconds time-interval 60
	set event-options policy MAC-LIMIT events SixtySeconds
	set event-options policy MAC-LIMIT then event-script mac_limit_guard.py
	# adjust this to be an admin user 
	set event-options event-script file mac_limit_guard.py python-script-user bryan

- SCP the file to the qfx /var/db/scripts/event/ directory.
	# ls /var/db/scripts/event/mac_limit_guard.py -al
	-rwxr-xr-x. 1 root root 13029 Mar  7 19:24 /var/db/scripts/event/mac_limit_guard.py

- Edit the /var/db/scripts/event/mac_limit_guard.py on the qfx and adjust the DEFAULTS

- monitor and test that this is running from junos
	bryan@QFX7> monitor start messages | match mac_limit_guard
	Mar  7 20:36:43  QFX7 cscript[1991]: CSCRIPT_SECURITY_WARNING: unsigned python script '/var/db/scripts/event/mac_limit_guard.py' without checksum is executed
	Mar  7 20:36:43  QFX7 mac_limit_guard[2002]: Starting scheduler loop: run_count=4, interval=15s
    Mar  7 20:37:28  QFX7 mac_limit_guard[5996]: Scheduler loop completed

- trace command for cscript
	show trace application cscript time 1

# Improvements
- Find some way to key this off a syslog event of learning a new MAC address.  Classic Junos can do this, but the 5130 is Junos (d)Evolved, and boy they really laid an egg with this.  So much basic stuff is missing.  There is 'show ethernet-switching mac-learning-log' but that's not something we can action items off of for syslog.  If this could be used, well it would solve all the crap of polling.   

# History of the problem
Below is the history/research I've done with this issue.

<pre>
Trying to set this at the switch level gives that it’s not found, but I can
set it and it complains in the config that it’s no supported. I’ve tried to do
the same at the default routing instance level and have the same results.
	bd@QFX7# set routing-instances MAC-VRF switch-options mac-
																		   ^
	'mac-' is ambiguous.
	Possible completions:
	mac-ip-table-size    Size of MAC+IP bindings table
	mac-move-limit       Number of MAC movements allowed on this VLAN
	mac-notification     MAC notification options
	[edit]

Sticky MAC which works, and I can see the MAC's learned on the port and
persistant across reboots.  This makes no sense to have sticky mac, but then
not be able to adjust the limits.
https://www.juniper.net/documentation/us/en/software/junos/security-services/topics/topic-map/understanding_and_using_persistent_mac_learning.html

I’ve tried the same on a QFX5100 and it works just fine. 
	set switch-options interface et-0/0/48 interface-mac-limit 16 packet-action drop-and-log

It was suggested this mac limit could be set using the 'mac-ip-limit' command,
but this is incorrect. This is the association of MAC to IP (ARP basically) in
the EVPN.  EVPN suppresses ARPs across the EVPN and uses this limit on an
interface/routing-instance/vlan to limit the MAC/IP mappings. A static mapping
here or sticky mapping is still the same as static arp. Even with this set to
1, I can still flood the port/EVPN/VLAN with thousands of MACs.  I'd really
like to be wrong about this

system {
    packet-forwarding-options {
        forwarding-profile {
            lpm-profile;
        }
    }
    processes {
        nlsd enable;
    }
}
routing-instances {
    MAC-VRF {
        instance-type mac-vrf;
        protocols {
            evpn {
                ##
                ## Warning: configuration block ignored: unsupported platform (qfx5130-48c)
                ##
                ##
                ## Warning: interface-mac-limit needs to be specified under switch-options for a virtual-switch or mac-vrf instance
                ##
                interface-mac-limit {
                    40;
                    packet-action drop;
                }
                encapsulation vxlan;
                extended-vni-list all;
            }
        }
        vtep-source-interface lo0.0 inet6;
        switch-options {
            mac-ip-table-size {
                16;
            }
            ##
            ## Warning: configuration block ignored: unsupported platform (qfx5130-48c)
            ##
            interface-mac-limit {
                16;
                packet-action drop;
            }
            interface ae0.0 {
                ##
                ## Warning: configuration block ignored: unsupported platform (qfx5130-48c)
                ##
                interface-mac-limit {
                    10;
                    packet-action drop;
                }
                persistent-learning;
            }
        }
        service-type vlan-aware;
        interface et-0/0/17.0;
        interface ae0.0;
        route-distinguisher 100.64.184.224:5000;
        vrf-target target:62475:5000;
        vlans {
            TEST-LAN {
                vlan-id 10;
                l3-interface irb.10;
                forwarding-options {
                    filter {
                        input ETHER-EVPN; ## reference 'ETHER-EVPN' not found
                    }
                }
                switch-options {
                    mac-ip-table-size {
                        16;
                    }
                    mac-statistics;
                }
                vxlan {
                    vni 500010;
                }
            }
        }
    } 


</pre>