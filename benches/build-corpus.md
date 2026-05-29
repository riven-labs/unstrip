# Corpus build

Commands used to build the benchmark corpus. All produce stripped Linux amd64 ELF binaries.

```
mkdir corpus && cd corpus

# Smaller, crypto-heavy
go install -ldflags='-s -w' filippo.io/mkcert@v1.4.4

# Medium dep trees
go install -ldflags='-s -w' github.com/caddyserver/caddy/v2/cmd/caddy@v2.8.4
go install -ldflags='-s -w' github.com/cli/cli/v2/cmd/gh@v2.55.0

# Largest: pulls in k8s.io/api, openapi-gen, etc.
go install -ldflags='-s -w' helm.sh/helm/v3/cmd/helm@v3.15.4

# Move into corpus dir with consistent naming
for f in caddy gh helm mkcert; do
    cp ~/go/bin/$f ./$f.linux-amd64.stripped
done
```

## Synthetic stress binary

[`testdata/complex/`](../testdata/complex/) is a deliberately complex program exercising generics, embedded structs, deep interface chains, reflection, goroutine pipelines, and the AWS SDK. Build with:

```
cd testdata/complex
go build -ldflags='-s -w' -o ~/corpus/complex.linux-amd64.stripped .
```

## Obfuscated build

For anti-analysis testing, the same source built through garble:

```
go install mvdan.cc/garble@v0.13.0
cd testdata/complex
garble -literals build -ldflags='-s -w' -o ~/corpus/complex.garbled.stripped .
```

Note: garble v0.16+ requires Go 1.26+. For older Go toolchains, pin to v0.13.
