# ping-pong

ping-pong is a sctp example that shows how you can send/recv messages.
In this example, there are 2 types of peers: **ping** and **pong**.

**Ping** will always send `ping <seq_number>` messages to **pong** and receive `pong <seq_number>` messages from **pong**.

**Pong** will always receive `ping <seq_number>` from **ping** and send `pong <seq_number>` messages to **ping**.

## Instruction

### Run ping and pong

### Run pong

```sh
go run github.com/pion/sctp/examples/ping-pong/pong@latest
```


### Run ping

```sh
go run github.com/pion/sctp/examples/ping-pong/ping@latest
```
