# gomonero
gomonero is an implementation of monero in Go (very early work in progress)

currently, there are only utilities for working with various address formats

the goal is to have a simple, readable, well documented, and performant implementaion of monero

this will make monero more accessible to community members wishing to contribute

immediate focus is on implementing the upcoming jamtis and seraphis specifications

## build, test, and benchmark

go get https://github.com/WernerVasquez/gomonero


to build (within gomonero directory):

go build ./...


to test (within gomonero directory):

go test -v ./...


to run benchmarks (within gomonero directory):

go test ./... -bench=.
