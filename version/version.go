package version

import "fmt"

var Version string

var (
	Name         string
	HumanVersion = fmt.Sprintf("%s v%s", Name, Version)
)
