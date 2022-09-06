package version

import "fmt"

const Version = "0.1.4"

var (
	Name         string
	HumanVersion = fmt.Sprintf("%s v%s", Name, Version)
)
