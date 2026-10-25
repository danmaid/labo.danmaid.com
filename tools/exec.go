endpoints:
  messages:
    type: exec
    line: tail -f /var/log/messages

  uart1:
    type: serial
    device: /dev/ttyUSB0
