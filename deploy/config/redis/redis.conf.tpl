# Redis config for an app node. Rendered once by sync-config.sh and then owned
# by Redis itself.
#
# IMPORTANT: sync-config.sh never overwrites an existing redis.conf on a host.
# During failover the standby runs `REPLICAOF NO ONE` followed by
# `CONFIG REWRITE`, which strips the replicaof line from this file. Re-rendering
# it would silently demote a promoted primary on the next container restart.

bind 0.0.0.0
protected-mode yes
port 6379

requirepass @@REDIS_PASSWORD@@
masterauth @@REDIS_PASSWORD@@

appendonly yes
appendfsync everysec
dir /data

# Replicas serve stale reads rather than errors while catching up.
replica-serve-stale-data yes
replica-read-only yes

# Standby nodes get a replicaof line here; the primary gets nothing.
@@REPLICAOF@@
