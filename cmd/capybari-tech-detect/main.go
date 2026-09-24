// Command capybari-tech-detect runs this capability on its own.
package main

import (
	techdetect "github.com/capybari-repo/capybari-analyzer-tech-detect"
	"github.com/capybari-repo/capybari-core/standalone"
)

var version = "dev"

func main() { standalone.Main(version, techdetect.New()) }
