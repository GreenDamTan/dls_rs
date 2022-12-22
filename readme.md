# Nvidia Delegated License Service

dls implementation in rust.

## Requirement

- Any os with redis
- rust stable toolchain

## Usage

clone this repo

```
cd dls_rs
cargo build --release
```

copy `target/release/nv_ls` to your dir.

and run with
`./nv_ls`

change config file `./data/config.json` as follows.

Once the configuration file has been modified, restart nv_ls to make it effective

## config.json

### server_addr

The service listener addr.

### server_port

The service listener port.

### domain

Automatic generation of ssl certificates for domain names.

If you have a certificate, you do not need to change anything.

### req_host

The host filled in the client's token, it is also the address of the client request

### req_port

The port filled in the client's token, it is also the port of the client request

### redis_url

Same as the name

### redis_task_interval

How often to automatically clean up the client release inside redis.

### scope_ref_list

Whatever, just let it as is, or ur can random some uuid v4, but keep in mind it only takes two

### nls_service_instance_ref

Whatever, just let it as is, or ur can random a new uuid v4

### lease_time

Client lease time, In second

### lease_renewal_factor

The interval factor between client vm requests to the server, expressed as a percentage.

*lease_time* * *lease_renewal_factor*

e.g:

lease_time: 600s, lease_renewal_factor: 20, time now: 2022/12/03 10:00:00

It means, The time of the next client request time is: 2022/12/03 10:02:00, and next time is 2022/12/03 10:04:00 till the client lease renew

### cert_https

Same as the name

### rsa_client_token

For vm client token encryption and vm-side verification of signatures, can delete the corresponding file and generate it again randomly







## Get vm client token

just access  `https://ur-ip-addr:server_port/genClientToken`
