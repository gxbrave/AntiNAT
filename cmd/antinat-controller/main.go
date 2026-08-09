package main

import (
	"fmt"
	"os"

	"github.com/gxbrave/AntiNAT/internal/buildinfo"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("antinat-controller %s\n", buildinfo.Format(buildinfo.Current()))
		return
	}

	fmt.Println("antinat-controller: bootstrap binary; controller services are not enabled yet")
}
