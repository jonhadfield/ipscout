# findexec


[![travisci][travisci-image]][travisci-url] [![codecov][codecov-image]][codecov-url] [![Go Report Card][go-report-card-image]][go-report-card-url]  [![GoDoc][godoc-image]][godoc-url]

A go library to find paths of executables

- [Usage](#usage)
- [License](#License)
- [Credits](#Credits)

## Usage

```go
package main

import "github.com/jonhadfield/findexec"

func main() {
    // find an executable called "diff" without specifying paths which will force
    // searching of the system paths found in environment variable 'PATH'
    _ = findexec.Find("diff", "")
    
    // find an executable called "bash" in specific paths
    _ = findexec.Find("bash", "/home/bin:/bin:/usr/local/bin")
}
```  

## License

The source code is made available under the terms of the Unlicense License, as stated in the file [LICENSE](LICENSE).

## Credits

This is rewrite of the [find_executable()](https://docs.python.org/2/distutils/apiref.html#module-distutils.spawn) function provided in the python 2 standard library.


[travisci-image]: https://travis-ci.org/jonhadfield/findexec.svg?branch=master
[travisci-url]: https://travis-ci.org/jonhadfield/findexec
[go-report-card-url]: https://goreportcard.com/report/github.com/jonhadfield/findexec
[go-report-card-image]: https://goreportcard.com/badge/github.com/jonhadfield/findexec
[codecov-image]: https://codecov.io/gh/jonhadfield/findexec/branch/master/graph/badge.svg
[codecov-url]: https://codecov.io/gh/jonhadfield/findexec
[godoc-image]: https://godoc.org/github.com/jonhadfield/findexec?status.svg
[godoc-url]: http://godoc.org/github.com/jonhadfield/findexec