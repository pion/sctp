# ping-pong

ping-pong is a sctp example that shows how you can send/recv messages.
In this example, there are 2 types of peers: **ping** and **pong**.

**Ping** will always send `ping <seq_number>` messages to **pong** and receive `pong <seq_number>` messages from **pong**.

**Pong** will always receive `ping <seq_number>` from **ping** and send `pong <seq_number>` messages to **ping**.

## Instruction

### Build ping and pong

```sh
make
```

### Run pong

```sh
./pong
```


### Run ping

```sh
./ping
```