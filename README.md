# ssh-keys-db

This maintains a list of SSH public keys to help to sort out which belongs to whom when dealing with hundreds of keys.

Sorry the docs suck. Please read the very messy code to figure out details of how it works.

## Install:

```
go get github.com/rtlong/ssh-keys-db
export SSH_KEYS_DB="$PWD/test.json"
ssh-keys-db --help
```
