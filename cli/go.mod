module github.com/swapnilsparsh/devsVPN/cli

go 1.23.0

toolchain go1.23.8

require (
	github.com/swapnilsparsh/devsVPN/daemon v0.0.0
	golang.org/x/crypto v0.39.0
	golang.org/x/sys v0.33.0
	golang.org/x/term v0.32.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/deckarep/golang-set/v2 v2.7.0 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/nftables v0.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/go-envparse v0.1.0 // indirect
	github.com/kocmo/go-xtables v1.0.8 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42 // indirect
	github.com/mdlayher/socket v0.5.0 // indirect
	github.com/olekukonko/tablewriter v0.0.5 // indirect
	github.com/panta/machineid v1.0.2 // indirect
	github.com/parsiya/golnk v0.0.0-20221103095132-740a4c27c4ff // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rivo/uniseg v0.4.4 // indirect
	github.com/stretchr/testify v1.8.4 // indirect
	github.com/vishvananda/netlink v1.3.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sync v0.15.0 // indirect
	golang.zx2c4.com/wireguard/windows v0.5.3 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/swapnilsparsh/devsVPN/daemon => ../daemon
