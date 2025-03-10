# Installation Instructions

```sh
go build .
sudo useradd -r -U gofetchgh
sudo install -o gofetchgh -g gofetchgh -D gofetchgh /opt/gofetchgh/gofetchgh
sudo install -o gofetchgh -g gofetchgh -D .env /opt/gofetchgh/.env
sudo cp gofetchgh.service /etc/systemd/system/
```
