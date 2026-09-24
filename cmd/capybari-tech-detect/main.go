// Command capybari-tech-detect runs this capability on its own.
package main

import (
	techdetect "github.com/capybari/capybari-analyzer-tech-detect"
	"github.com/capybari/capybari-core/standalone"
)

var version = "dev"

func main() { standalone.Main(version, techdetect.New()) }
