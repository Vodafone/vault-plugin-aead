package version

import "fmt"

const Version = "0.1.2"

var (
	Name         string
	HumanVersion = fmt.Sprintf("%s v%s", Name, Version)
)
