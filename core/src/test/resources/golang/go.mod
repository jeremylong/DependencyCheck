module my/thing

require github.com/ethereum/go-ethereum v1.8.17

require (
	github.com/go-gitea/gitea v1.5.0
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a // indirect
)

replace bad/thing v1.4.5 => good/thing v1.4.5
