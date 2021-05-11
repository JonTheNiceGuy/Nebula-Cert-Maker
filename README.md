# Nebula-Cert-Maker

A script which allows you to create new host certificates and keys

Originally written for an offline Nebula CA for my home network and VPS, this script uses features
in the Nebula Certificate Authority certificate to pre-fill certain fields that help with my Nebula
overlay network.

## Create the CA

I'm using a Raspberry Pi that I can boot offline from the rest of my network. I generated my root
certificate like this:

`nebula-cert ca -ips 192.0.2.0/24 -name nebula.example.org`

By generating the CA certificate like this, I can derive the DNS search domain
(`somehost.nebula.example.org`) and the base CIDR for the nodes on the network.

This certificate defaults to 1 year (or 8760 hours), so after 6 months, a second CA would need to
be generated in order to ensure that the certificates you have created don't expire. (You can put
longer durations in, but I'm electing to keep it as 1 year. Ideally, I'd be doing ACME style
certificate management with a 3 month span... but... not yet!)

## Using the tool

`certmaker.sh` has help, which can be exposed using `./certmaker.sh --help` or running it with no
parameters.

With the most simple action, running `./certmaker.sh --name somehost` (which can also be run as
`./certmaker.sh -n somehost`), you'll get a random IP address in the first defined subnet in the
CA cert. If you've not defined a subnet in the CA Cert, then you'll get an IP address in the subnet
10.44.88.0/24 (which was picked at random by the author). The hostname will be defined as
`somehost.nebula.example.org`, or whatever suffix the CA cert has specified as the CA Name.

If you want to specify one or more specific FQDN suffixes, you can also use the `-f` or
`--fqdn_root` flag, like this `./certmaker.sh -n somehost -f nebula.example.net`. (Remember that
the `-f` and and `-n` flags expand to `--fqdn_root` and `--name` respectively.)

If you want to add a specific IP to the subnet, perhaps if you want your lighthouses to be
192.0.2.1, for example, you can use the `-i` or `--ip` flag, like this
`./certmaker.sh -n lighthouse -i 1`. (Again, `-i` expands to `--ip`.)

If your CA has multiple permitted subnets, perhaps `["192.0.2.0/24","198.51.100.0/24"]`, you can
use the `-d` or `--index` flag to tell it which subnet base to use, where 0 would be `192.0.2.0/24`
and 1 would be `198.51.100.0/24` in this context. By default, it will pick the first subnet.

If the CA does not have a subnet defined, `certmaker.sh` will default to using `10.44.88.0/24`. You
can manually specify a subnet to use, with the `-b` or `--subnet` flag, like this
`./certmaker.sh -n somehost -b "203.0.113.0/24"`. (As before, `-b` expands to `--subnet`.)

This script assumes that you will be generating certificates in `/root/nebula`. If this is not the
case, you can specify the path to your CA key and certificate files with the `-c` or `--cert_path`
flags, like this `./certmaker.sh -n somehost -c /tmp/certmaker`. Note that this flag will check for
both `ca.crt` and `ca.key` in this path.

Lastly, a key function of Nebula is the use of groups to define a firewall policy. Three basic and
common groups have been defined with a collection of simple flags, which are:

* `-l`/`--lighthouse`
* `-s`/`--server`
* `-w`/`--workstation`

These flags will assign the groups, respectively "`Lighthouse`", "`Server`" and "`Workstation`". If
you want to add additional groups, these can be assigned with the flag `-g` or `--group` and then
the group string, like this `./certmaker.sh -n somehost -g "ADevice" -l -s` which would add the
groups `Lighthouse`, `Server`, and `ADevice`.

Once you've put your command together, the script will generate a certificate and key, in the
current working directory, named for the name of the device.

If you've created the public key to use (perhaps on a mobile device) already, you may use the `-k`
or `--key` option to specify the path for that public key, like this
`./certmaker.sh -n mobile -k mobile.key`

## Putting it together

Let's build some certificates.

```bash
mkdir -p /tmp/nebula_ca
# Create the CA
nebula-cert ca -out-crt /tmp/nebula_ca/ca.crt -out-key /tmp/nebula_ca/ca.key -ips 192.0.2.0/24,198.51.100.0/24 -name nebula.example.org
# First lighthouse, lighthouse1.nebula.example.org - 192.0.2.1, group "Lighthouse"
./certmaker.sh --cert_path /tmp/nebula_ca --name lighthouse1 --ip 1 --lighthouse
# Second lighthouse, lighthouse2.nebula.example.org - 192.0.2.2, group "Lighthouse"
./certmaker.sh -c /tmp/nebula_ca -n lighthouse2 -i 2 -l
# First webserver, webserver1.nebula.example.org - 192.0.2.168, groups "Server" and "web"
./certmaker.sh --cert_path /tmp/nebula_ca --name webserver1 --server --group web
# Second webserver, webserver2.nebula.example.org - 192.0.2.191, groups "Server" and "web"
./certmaker.sh -c /tmp/nebula_ca -n webserver2 -s -g web
# Database Server, db.nebula.example.org - 192.0.2.182, groups "Server" and "db"
./certmaker.sh --cert_path /tmp/nebula_ca --name db --server --group db
# First workstation, admin1.nebula.example.org - 198.51.100.205, group "Workstation"
./certmaker.sh --cert_path /tmp/nebula_ca --index 1 --name admin1 --workstation
# Second workstation, admin2.nebula.example.org - 198.51.100.77, group "Workstation"
./certmaker.sh -c /tmp/nebula_ca -d 1 -n admin2 -w
```
