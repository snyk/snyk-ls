//go:build windows

/*
 * © 2026 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fileicon

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"syscall"
	"unsafe"
)

// Windows API constants.
const (
	fileAttributeNormal    = 0x00000080
	shgfiIcon              = 0x000000100
	shgfiSmallIcon         = 0x000000001
	shgfiUseFileAttributes = 0x000000010
	diNormal               = 0x0003
	dibRGBColors           = 0
)

// shFileInfo mirrors SHFILEINFOW from shellapi.h.
type shFileInfo struct {
	hIcon         uintptr
	iIcon         int32
	dwAttributes  uint32
	szDisplayName [260]uint16
	szTypeName    [80]uint16
}

// bitmapInfoHeader mirrors BITMAPINFOHEADER from wingdi.h.
type bitmapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

// Lazy-loaded Windows DLL procedures. Lazy loading ensures startup does not fail
// on systems where a particular DLL version is missing a specific procedure.
var (
	modShell32 = syscall.NewLazyDLL("shell32.dll")
	modGdi32   = syscall.NewLazyDLL("gdi32.dll")
	modUser32  = syscall.NewLazyDLL("user32.dll")

	procSHGetFileInfo      = modShell32.NewProc("SHGetFileInfoW")
	procCreateCompatibleDC = modGdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSection   = modGdi32.NewProc("CreateDIBSection")
	procSelectObject       = modGdi32.NewProc("SelectObject")
	procDeleteObject       = modGdi32.NewProc("DeleteObject")
	procDeleteDC           = modGdi32.NewProc("DeleteDC")
	procDrawIconEx         = modUser32.NewProc("DrawIconEx")
	procDestroyIcon        = modUser32.NewProc("DestroyIcon")
	procGetDesktopWindow   = modUser32.NewProc("GetDesktopWindow")
	procGetDC              = modUser32.NewProc("GetDC")
	procReleaseDC          = modUser32.NewProc("ReleaseDC")
)

// fetchOSFileIcon retrieves a 16×16 file-type icon for the given lowercase extension
// using SHGetFileInfoW (shell icon) + GDI (DIB rendering), then encodes the result as
// a base64 PNG data-URI inside an HTML <img> tag.
//
// SHGFI_USEFILEATTRIBUTES is set so the file does not need to exist on disk.
// A 32-bit DIB section is used so that the alpha channel is preserved for modern
// ARGB icons. For legacy mask-based icons where all alpha values are zero,
// pixels are treated as fully opaque (alpha = 255).
func fetchOSFileIcon(ext string) string {
	// Use a synthetic filename so the shell resolves the icon type by extension.
	fakePath := "file" + ext
	pathPtr, err := syscall.UTF16PtrFromString(fakePath)
	if err != nil {
		return ""
	}

	var info shFileInfo
	ret, _, _ := procSHGetFileInfo.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		fileAttributeNormal,
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
		shgfiIcon|shgfiSmallIcon|shgfiUseFileAttributes,
	)
	if ret == 0 || info.hIcon == 0 {
		return ""
	}
	defer procDestroyIcon.Call(info.hIcon)

	pngData, ok := hIconToPNG(info.hIcon, 16, 16)
	if !ok {
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(pngData)
	return fmt.Sprintf(`<img src="data:image/png;base64,%s" width="16" height="16"/>`, encoded)
}

// hIconToPNG renders hIcon into a width×height PNG.
// It allocates a 32-bit top-down DIB section so the pixel buffer is directly
// accessible without an additional GetDIBits call.
func hIconToPNG(hIcon uintptr, width, height int) ([]byte, bool) {
	hDesktop, _, _ := procGetDesktopWindow.Call()
	hScreenDC, _, _ := procGetDC.Call(hDesktop)
	if hScreenDC == 0 {
		return nil, false
	}
	defer procReleaseDC.Call(hDesktop, hScreenDC)

	hMemDC, _, _ := procCreateCompatibleDC.Call(hScreenDC)
	if hMemDC == 0 {
		return nil, false
	}
	defer procDeleteDC.Call(hMemDC)

	// A negative BiHeight means a top-down DIB, which simplifies row indexing.
	header := bitmapInfoHeader{
		BiSize:     uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		BiWidth:    int32(width),
		BiHeight:   -int32(height),
		BiPlanes:   1,
		BiBitCount: 32,
	}

	var pPixels unsafe.Pointer
	hDIB, _, _ := procCreateDIBSection.Call(
		hScreenDC,
		uintptr(unsafe.Pointer(&header)),
		dibRGBColors,
		uintptr(unsafe.Pointer(&pPixels)),
		0, 0,
	)
	if hDIB == 0 || pPixels == nil {
		return nil, false
	}
	defer procDeleteObject.Call(hDIB)

	prevBmp, _, _ := procSelectObject.Call(hMemDC, hDIB)
	defer procSelectObject.Call(hMemDC, prevBmp)

	procDrawIconEx.Call(hMemDC, 0, 0, hIcon, uintptr(width), uintptr(height), 0, 0, diNormal)

	const bytesPerPixel = 4
	totalBytes := width * height * bytesPerPixel

	// Access the pixel buffer written by DrawIconEx.
	//nolint:govet // unsafe.Pointer to slice is intentional and safe here
	pixelSlice := (*[1 << 20]byte)(pPixels)[:totalBytes:totalBytes]

	// Detect whether the DIB contains any real alpha data. Legacy XP-style icons
	// use AND-mask transparency and leave the alpha byte at zero; in that case we
	// treat every pixel as fully opaque so the icon is at least visible.
	hasAlpha := false
	for i := 3; i < totalBytes; i += bytesPerPixel {
		if pixelSlice[i] != 0 {
			hasAlpha = true
			break
		}
	}

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			i := (y*width + x) * bytesPerPixel
			b, g, r, a := pixelSlice[i], pixelSlice[i+1], pixelSlice[i+2], pixelSlice[i+3]
			if !hasAlpha {
				a = 255
			}
			img.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: a})
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}
