module github.com/ultramesh/flato-msp-cert

require (
	github.com/stretchr/testify v1.5.1
	github.com/ultramesh/crypto-gm v0.2.6
	github.com/ultramesh/crypto-standard v0.1.12
	golang.org/x/crypto v0.0.0-20190820162420-60c769a6c586
	golang.org/x/sys v0.0.0-20190412213103-97732733099d
)

replace github.com/ultramesh/crypto-gm => git.hyperchain.cn/ultramesh/crypto-gm.git v0.2.6

replace github.com/ultramesh/crypto-standard => git.hyperchain.cn/ultramesh/crypto-standard.git v0.1.12

go 1.13
