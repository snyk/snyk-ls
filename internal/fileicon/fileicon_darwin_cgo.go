//go:build darwin && cgo

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

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework AppKit -framework Foundation
#include <stdlib.h>
#import <AppKit/AppKit.h>

// fileTypeIconPNG returns a malloc'd buffer holding a 16×16 PNG for the
// file-type icon of the given extension (no leading dot).
// *outLen is set to the buffer size; returns NULL on failure.
// The caller must release the buffer with freeIconData.
static const unsigned char* fileTypeIconPNG(const char *ext, int *outLen) {
    @autoreleasepool {
        NSString *extStr = [NSString stringWithUTF8String:ext];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        NSImage *img = [[NSWorkspace sharedWorkspace] iconForFileType:extStr];
#pragma clang diagnostic pop
        if (!img) { *outLen = 0; return NULL; }
        [img setSize:NSMakeSize(16, 16)];
        NSData *tiff = [img TIFFRepresentation];
        if (!tiff) { *outLen = 0; return NULL; }
        NSBitmapImageRep *rep = [NSBitmapImageRep imageRepWithData:tiff];
        if (!rep) { *outLen = 0; return NULL; }
        NSData *png = [rep representationUsingType:NSBitmapImageFileTypePNG
                                       properties:[NSDictionary dictionary]];
        if (!png || [png length] == 0) { *outLen = 0; return NULL; }
        *outLen = (int)[png length];
        unsigned char *buf = (unsigned char *)malloc(*outLen);
        memcpy(buf, [png bytes], *outLen);
        return buf;
    }
}

static void freeIconData(const unsigned char *buf) {
    free((void *)buf);
}
*/
import "C"

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unsafe"
)

// fetchOSFileIcon retrieves the 16×16 file-type icon for the given lowercase
// extension via NSWorkspace.iconForFileType: and returns it as a base64-encoded
// PNG data-URI inside an HTML <img> tag.
//
// NSWorkspace always returns at least a generic document icon, so this function
// returns "" only when the PNG conversion itself fails.
func fetchOSFileIcon(ext string) string {
	// NSWorkspace.iconForFileType: expects the extension without the leading dot.
	typeStr := strings.TrimPrefix(ext, ".")

	cExt := C.CString(typeStr)
	defer C.free(unsafe.Pointer(cExt))

	var outLen C.int
	data := C.fileTypeIconPNG(cExt, &outLen)
	if data == nil || outLen == 0 {
		return ""
	}
	defer C.freeIconData(data)

	pngBytes := C.GoBytes(unsafe.Pointer(data), outLen)
	encoded := base64.StdEncoding.EncodeToString(pngBytes)
	return fmt.Sprintf(`<img src="data:image/png;base64,%s" width="16" height="16"/>`, encoded)
}
