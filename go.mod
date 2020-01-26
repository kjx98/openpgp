module github.com/kjx98/openpgp

go 1.11

require golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2

replace (
	golang.org/x/crypto => github.com/golang/crypto v0.0.0-20190308221718-c2843e01d9a2
	golang.org/x/net => github.com/golang/net v0.0.0-20190628185345-da137c7871d7
	golang.org/x/sys => github.com/golang/sys v0.0.0-20190712062909-fae7ac547cb7
	golang.org/x/text v0.3.0 => github.com/golang/text v0.3.0
)
