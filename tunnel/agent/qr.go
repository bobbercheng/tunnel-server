package main

import (
	"fmt"
	"strings"

	"rsc.io/qr"
)

// printQR renders a QR code in the terminal using Unicode half-block characters.
// Two rows of QR modules are combined into one terminal line using ▀▄█ and space.
func printQR(url string) {
	code, err := qr.Encode(url, qr.L)
	if err != nil {
		fmt.Printf("(QR generation failed: %v)\n", err)
		return
	}

	size := code.Size
	var sb strings.Builder

	sb.WriteString("\n")
	// Process two rows at a time using Unicode half-block characters
	for y := 0; y < size; y += 2 {
		sb.WriteString("  ") // left margin
		for x := 0; x < size; x++ {
			top := code.Black(x, y)
			bot := y+1 < size && code.Black(x, y+1)
			switch {
			case top && bot:
				sb.WriteRune('█')
			case top && !bot:
				sb.WriteRune('▀')
			case !top && bot:
				sb.WriteRune('▄')
			default:
				sb.WriteRune(' ')
			}
		}
		sb.WriteString("\n")
	}

	fmt.Print(sb.String())
}
