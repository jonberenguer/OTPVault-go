package main

import (
	"fmt"
	"image"
	"image/color"
	"math"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// CountdownCircle draws a circular arc that depletes clockwise from 12 o'clock.
// The remaining seconds are shown centred inside the ring.
type CountdownCircle struct {
	widget.BaseWidget
	remaining int
	period    int
}

func NewCountdownCircle(remaining, period int) *CountdownCircle {
	c := &CountdownCircle{remaining: remaining, period: period}
	c.ExtendBaseWidget(c)
	return c
}

func (c *CountdownCircle) MinSize() fyne.Size { return fyne.NewSize(44, 44) }

func (c *CountdownCircle) CreateRenderer() fyne.WidgetRenderer {
	arc := canvas.NewImageFromImage(c.renderArc(88))
	arc.FillMode = canvas.ImageFillContain

	num := widget.NewLabel(fmt.Sprintf("%d", c.remaining))
	num.Alignment = fyne.TextAlignCenter
	num.TextStyle = fyne.TextStyle{Monospace: true, Bold: true}

	return &circleRenderer{
		w:    c,
		arc:  arc,
		num:  num,
		over: container.NewCenter(num),
	}
}

// renderArc pre-renders the ring into a square NRGBA image at the given pixel size.
// Rendering at 2× the widget's logical size then scaling down gives smoother edges.
func (c *CountdownCircle) renderArc(size int) image.Image {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))

	cx := float64(size-1) / 2
	cy := float64(size-1) / 2
	outer := math.Min(cx, cy) - 1
	inner := outer - math.Max(6, outer*0.18)

	fraction := 0.0
	if c.period > 0 {
		fraction = float64(c.remaining) / float64(c.period)
	}
	threshold := fraction * 2 * math.Pi

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx := float64(x) - cx
			dy := float64(y) - cy
			dist := math.Sqrt(dx*dx + dy*dy)

			if dist < inner || dist > outer {
				continue
			}

			// Clockwise angle from 12 o'clock: atan2(dx, -dy) = 0 at top.
			angle := math.Atan2(dx, -dy)
			if angle < 0 {
				angle += 2 * math.Pi
			}

			// Sub-pixel anti-aliasing at both ring edges.
			aa := math.Min(outer-dist, dist-inner)
			alpha := uint8(255)
			if aa < 1.5 {
				alpha = uint8(aa / 1.5 * 255)
			}

			var col color.NRGBA
			if angle < threshold {
				if fraction <= 0.25 {
					col = color.NRGBA{R: 230, G: 70, B: 70, A: alpha}
				} else {
					col = color.NRGBA{R: 79, G: 209, B: 197, A: alpha}
				}
			} else {
				col = color.NRGBA{R: 55, G: 55, B: 75, A: alpha}
			}
			img.SetNRGBA(x, y, col)
		}
	}
	return img
}

// ── Renderer ───────────────────────────────────────────────────────────────

type circleRenderer struct {
	w    *CountdownCircle
	arc  *canvas.Image
	num  *widget.Label
	over *fyne.Container // container.NewCenter wrapping num
}

func (r *circleRenderer) Layout(size fyne.Size) {
	r.arc.Resize(size)
	r.arc.Move(fyne.NewPos(0, 0))
	r.over.Resize(size)
	r.over.Move(fyne.NewPos(0, 0))
}

func (r *circleRenderer) MinSize() fyne.Size { return r.w.MinSize() }

func (r *circleRenderer) Refresh() {
	r.arc.Image = r.w.renderArc(88)
	r.num.SetText(fmt.Sprintf("%d", r.w.remaining))
	canvas.Refresh(r.arc)
	r.over.Refresh()
}

func (r *circleRenderer) Destroy() {}

func (r *circleRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.arc, r.over}
}
