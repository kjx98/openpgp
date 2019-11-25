module github.com/kjx98/openpgp

go 1.11

require (
	github.com/kjx98/crypto v0.0.0-20191124041549-d5e3a4ab447c
	golang.org/x/crypto v0.0.0
	golang.org/x/net v0.0.0
	golang.org/x/sys v0.0.0
)

replace (
	golang.org/x/crypto => github.com/golang/crypto v0.0.0-20190513172903-22d7a77e9e5f
	golang.org/x/net => github.com/golang/net v0.0.0-20190404232315-eb5bcb51f2a3
	golang.org/x/sys => github.com/golang/sys v0.0.0-20190412213103-97732733099d
)
