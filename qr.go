package main

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	qrcode "github.com/skip2/go-qrcode"
)

func showQRDialog(acc Account, secret string) {
	if secret == "" {
		dialog.ShowError(fmt.Errorf("secret not available for this account"), mainWindow)
		return
	}

	uri := formatOtpAuthURI(acc.Name, acc.Issuer, secret, acc.Type, acc.Counter, acc.Digits, acc.Period)

	png, err := qrcode.Encode(uri, qrcode.Medium, 300)
	if err != nil {
		dialog.ShowError(fmt.Errorf("failed to generate QR code: %w", err), mainWindow)
		return
	}

	res := fyne.NewStaticResource("qr.png", png)
	img := canvas.NewImageFromResource(res)
	img.FillMode = canvas.ImageFillOriginal
	img.SetMinSize(fyne.NewSize(300, 300))

	note := widget.NewLabel("Scan with any TOTP authenticator app.\nContains your plaintext secret — keep it private.")
	note.Wrapping = fyne.TextWrapWord
	note.Alignment = fyne.TextAlignCenter

	title := acc.Name
	if acc.Issuer != "" {
		title = acc.Issuer + " — " + acc.Name
	}

	d := dialog.NewCustom(title, "Close", container.NewVBox(note, img), mainWindow)
	d.Resize(fyne.NewSize(360, 420))
	d.Show()
}
