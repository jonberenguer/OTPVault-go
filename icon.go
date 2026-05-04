package main

import (
	_ "embed"

	"fyne.io/fyne/v2"
)

//go:embed Icon.png
var iconBytes []byte

var appIcon = fyne.NewStaticResource("Icon.png", iconBytes)
