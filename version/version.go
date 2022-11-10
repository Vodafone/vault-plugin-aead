package version

import "fmt"

const Version = "0.1.6"

var (
	Name         string
	HumanVersion = fmt.Sprintf("%s v%s", Name, Version)
)
